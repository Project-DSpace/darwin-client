//! Compacting a manifest: replacing embedded DataMaps with the addresses
//! their files are readable at.
//!
//! An embedded DataMap can become an address only once its file is readable
//! by address on the network. Planning finds out which entries already are,
//! and in which form ([`PublicForm`]): the readable envelope that
//! `darwin file upload --public` stores (unlisted) or that
//! `--visibility listed` stores, or a plain DataMap chunk, as an upload
//! stores one that hides every payment field and has no metadata. An entry
//! readable in none of these forms stays embedded: compacting publishes
//! nothing, so it never stores a DataMap without its envelope.
//!
//! Every address here is derived from the embedded DataMap itself; nothing a
//! manifest's author wrote can point compaction at other content. A readable
//! envelope has no salt, so its address follows from the DataMap alone, for
//! the root map as for its published (shrunk) form. An upload with metadata
//! (a name or content type) or with hidden payment fields stores its
//! envelope at an address that can't be derived this way; a manifest names
//! such a file by its address instead.

use std::collections::BTreeSet;

use ant_protocol::compute_address;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::data::client::envelope::EnvelopeOptions;
use crate::data::Client;

use super::{published_data_map, ContentRef, Manifest, ManifestError, ADDRESS_LEN};

use self_encryption::DataMap;

#[cfg(test)]
use super::ManifestEntry;
#[cfg(test)]
use self_encryption::ChunkInfo;
#[cfg(test)]
use xor_name::XorName;

/// Existence checks run against the network at once while planning.
const PLAN_CONCURRENCY: usize = 8;

/// A form in which a file is readable by an address its DataMap alone gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicForm {
    /// The envelope `darwin file upload --public` stores: readable, not in
    /// the index, every payment field shown, no metadata
    /// ([`EnvelopeOptions::unlisted`]).
    UnlistedEnvelope,
    /// The same envelope in the index, as `--visibility listed` stores it
    /// ([`EnvelopeOptions::listed`]).
    ListedEnvelope,
    /// A plain DataMap chunk, as an upload stores one that is readable, not
    /// in the index, hides every payment field and has no metadata.
    Plain,
}

impl PublicForm {
    /// Every form, in the order planning checks them.
    pub const ALL: [Self; 3] = [Self::UnlistedEnvelope, Self::ListedEnvelope, Self::Plain];

    /// The address the file `data_map` describes has in this form. The root
    /// map and its published (shrunk) form give the same address.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Encode`] if the DataMap can't be shrunk or
    /// encoded, or no envelope can be built for it.
    pub fn address(self, data_map: &DataMap) -> Result<[u8; ADDRESS_LEN], ManifestError> {
        self.address_of_published(&published_data_map(data_map)?)
    }

    /// [`Self::address`] for a DataMap already in its published form.
    fn address_of_published(self, published: &DataMap) -> Result<[u8; ADDRESS_LEN], ManifestError> {
        let options = match self {
            Self::UnlistedEnvelope => EnvelopeOptions::unlisted(),
            Self::ListedEnvelope => EnvelopeOptions::listed(),
            Self::Plain => {
                let bytes = rmp_serde::to_vec(published).map_err(|e| {
                    ManifestError::Encode(format!("DataMap did not serialize: {e}"))
                })?;
                return Ok(compute_address(&bytes));
            }
        };
        let envelope = options
            .envelope(published, None)
            .map_err(|e| ManifestError::Encode(format!("no envelope fits this DataMap: {e}")))?;
        Ok(envelope.address())
    }
}

/// One embedded entry, and where its file is readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedEntry {
    /// Index into `manifest.entries`.
    pub index: usize,
    /// Effective name, for display.
    pub name: String,
    /// In [`CompactPlan::already_public`], the address the file is readable
    /// at, in `form`. In [`CompactPlan::needs_publish`], the entry's identity
    /// ([`ContentRef::content_address`]), where nothing readable is stored.
    pub address: [u8; ADDRESS_LEN],
    /// The form the file is readable in at `address`; `None` in
    /// [`CompactPlan::needs_publish`].
    #[serde(default)]
    pub form: Option<PublicForm>,
}

/// What compacting a manifest would involve.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactPlan {
    /// Embedded entries whose file is already readable by an address.
    pub already_public: Vec<EmbeddedEntry>,
    /// Embedded entries readable by no address yet. Compacting leaves them
    /// embedded.
    pub needs_publish: Vec<EmbeddedEntry>,
}

impl CompactPlan {
    /// Whether every embedded entry can be compacted without publishing.
    pub fn is_free(&self) -> bool {
        self.needs_publish.is_empty()
    }

    /// Indices of every embedded entry in the plan.
    pub fn all_indices(&self) -> BTreeSet<usize> {
        self.already_public
            .iter()
            .chain(&self.needs_publish)
            .map(|e| e.index)
            .collect()
    }
}

/// Check every embedded entry against the network, several at a time: the
/// first [`PublicForm`] in which its file is stored, in the order of
/// [`PublicForm::ALL`]. Reads only; pays and stores nothing. Entries in the
/// plan keep manifest order.
pub async fn plan_compaction(
    client: &Client,
    manifest: &Manifest,
    cancel: &CancellationToken,
) -> Result<CompactPlan, ManifestError> {
    let mut embedded = Vec::new();
    for (index, entry) in manifest.entries.iter().enumerate() {
        if let ContentRef::Embedded { data_map } = &entry.source {
            let published = published_data_map(data_map)?;
            let mut candidates = Vec::with_capacity(PublicForm::ALL.len());
            for form in PublicForm::ALL {
                candidates.push((form, form.address_of_published(&published)?));
            }
            embedded.push((
                EmbeddedEntry {
                    index,
                    name: entry.effective_name()?,
                    address: entry.source.content_address()?,
                    form: None,
                },
                candidates,
            ));
        }
    }

    let checks = stream::iter(embedded)
        .map(|(entry, candidates)| async move {
            let found = first_stored(client, &candidates).await;
            (entry, found)
        })
        .buffer_unordered(PLAN_CONCURRENCY)
        .collect::<Vec<_>>();
    let mut results = tokio::select! {
        _ = cancel.cancelled() => return Err(ManifestError::Cancelled),
        results = checks => results,
    };
    results.sort_by_key(|(entry, _)| entry.index);

    let mut plan = CompactPlan::default();
    for (mut entry, found) in results {
        match found? {
            Some((form, address)) => {
                entry.form = Some(form);
                entry.address = address;
                plan.already_public.push(entry);
            }
            None => plan.needs_publish.push(entry),
        }
    }
    Ok(plan)
}

/// The first of `candidates` stored on the network, asked in order.
async fn first_stored(
    client: &Client,
    candidates: &[(PublicForm, [u8; ADDRESS_LEN])],
) -> Result<Option<(PublicForm, [u8; ADDRESS_LEN])>, ManifestError> {
    for &(form, address) in candidates {
        if client.chunk_exists(&address).await? {
            return Ok(Some((form, address)));
        }
    }
    Ok(None)
}

/// Store the published DataMap chunk of each entry in `entries`, with no
/// envelope. Paid; makes those files public. Returns the addresses stored,
/// in the same order.
///
/// Held back: nothing calls it, and it is not exported. A file published
/// this way has no envelope, so no payment record or listing, and a file
/// already readable in an envelope would get a second address. Publishing
/// from compaction comes back as an envelope stored the way
/// `darwin file upload --visibility unlisted` stores one.
///
/// Before anything is paid for, every entry is checked: it must be embedded,
/// its published map must hash to the planned address, and when that map
/// is shrunk, the wrapper records it points at must be on the network, or
/// the published chunk would not resolve. Cancellation is honoured between
/// stores, never in the middle of one.
#[expect(
    dead_code,
    reason = "held back: compaction publishes nothing until it stores envelopes"
)]
pub(crate) async fn publish_data_maps(
    client: &Client,
    manifest: &Manifest,
    entries: &[EmbeddedEntry],
    cancel: &CancellationToken,
) -> Result<Vec<[u8; ADDRESS_LEN]>, ManifestError> {
    let mut to_store = Vec::with_capacity(entries.len());
    for embedded in entries {
        if cancel.is_cancelled() {
            return Err(ManifestError::Cancelled);
        }
        let entry = manifest.entries.get(embedded.index).ok_or_else(|| {
            ManifestError::Build(format!("entry {} is out of range", embedded.index))
        })?;
        if entry.source.content_address()? != embedded.address {
            return Err(ManifestError::Build(format!(
                "entry {} does not match the compaction plan",
                embedded.name
            )));
        }
        let ContentRef::Embedded { data_map } = &entry.source else {
            return Err(ManifestError::Build(format!(
                "entry {} is not embedded",
                embedded.name
            )));
        };
        let published = published_data_map(data_map)?;
        if published.is_child() {
            for info in published.infos() {
                if !client.chunk_exists(&info.dst_hash.0).await? {
                    return Err(ManifestError::Build(format!(
                        "entry {} cannot be published: its wrapper record {} is not on the network",
                        embedded.name,
                        hex::encode(info.dst_hash.0)
                    )));
                }
            }
        }
        to_store.push((embedded, published));
    }

    let mut stored = Vec::with_capacity(to_store.len());
    for (embedded, published) in to_store {
        if cancel.is_cancelled() {
            return Err(ManifestError::Cancelled);
        }
        let address = client.data_map_store(&published).await?;
        if address != embedded.address {
            return Err(ManifestError::Build(format!(
                "entry {} stored at an unexpected address",
                embedded.name
            )));
        }
        stored.push(address);
    }
    Ok(stored)
}

/// Replace each entry of `plan.already_public` with the address its file is
/// readable at, in the form the plan found, derived again from the entry's
/// DataMap. Every other entry, those in `plan.needs_publish` included, is
/// left as it is.
///
/// # Errors
///
/// Returns [`ManifestError::Build`] if a planned entry is out of range, has
/// no form, or its DataMap no longer gives the planned address.
pub fn apply_compaction(
    manifest: &Manifest,
    plan: &CompactPlan,
) -> Result<Manifest, ManifestError> {
    let mut compacted = manifest.clone();
    for planned in &plan.already_public {
        let entry = compacted.entries.get_mut(planned.index).ok_or_else(|| {
            ManifestError::Build(format!("entry {} is out of range", planned.index))
        })?;
        let ContentRef::Embedded { data_map } = &entry.source else {
            // Already an address.
            continue;
        };
        let form = planned.form.ok_or_else(|| {
            ManifestError::Build(format!(
                "entry {} has no public form in the compaction plan",
                planned.name
            ))
        })?;
        // Derived from the DataMap, so the entry keeps its content.
        let address = form.address(data_map)?;
        if address != planned.address {
            return Err(ManifestError::Build(format!(
                "entry {} does not match the compaction plan",
                planned.name
            )));
        }
        entry.source = ContentRef::Public { address };
    }
    Ok(compacted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::data::manifest::data_map_address;
    use ant_listings::{Envelope, Metadata, ShownFields};

    fn data_map(seed: u8) -> DataMap {
        DataMap::new(vec![ChunkInfo {
            index: 0,
            dst_hash: XorName([seed; 32]),
            src_hash: XorName([seed; 32]),
            src_size: 10,
        }])
    }

    /// A root DataMap of `chunks` synthetic chunks, which publishing shrinks
    /// when there are more than three.
    fn root_map(chunks: usize, seed: u8) -> DataMap {
        DataMap::new(
            (0..chunks)
                .map(|index| ChunkInfo {
                    index,
                    dst_hash: XorName([seed.wrapping_add(index as u8); 32]),
                    src_hash: XorName([seed.wrapping_mul(3).wrapping_add(index as u8); 32]),
                    src_size: 4096,
                })
                .collect(),
        )
    }

    fn embedded(path: &str, data_map: DataMap) -> ManifestEntry {
        ManifestEntry {
            path: Some(path.into()),
            size: None,
            source: ContentRef::Embedded { data_map },
        }
    }

    /// The envelope `darwin file upload --public` stores, an unlisted one,
    /// has an address the DataMap alone gives: from the root map a manifest
    /// embeds as from the published (shrunk) map the upload stored, since a
    /// readable envelope has no salt. The same holds for a listed one.
    #[test]
    fn the_default_readable_envelope_address_follows_from_the_map() {
        let root = root_map(8, 0x10);
        let shrunk = published_data_map(&root).unwrap();
        assert!(shrunk.is_child(), "eight chunks are shrunk when published");
        assert_eq!(published_data_map(&shrunk).unwrap(), shrunk);

        for (form, options, in_index) in [
            (
                PublicForm::UnlistedEnvelope,
                EnvelopeOptions::unlisted(),
                false,
            ),
            (PublicForm::ListedEnvelope, EnvelopeOptions::listed(), true),
        ] {
            let expected = options.envelope(&shrunk, None).unwrap().address();
            assert_eq!(form.address(&root).unwrap(), expected, "{form:?}, root map");
            assert_eq!(
                form.address(&shrunk).unwrap(),
                expected,
                "{form:?}, shrunk map"
            );
            // Readable, every payment field shown, no metadata.
            let readable =
                Envelope::readable(&shrunk, Metadata::default(), ShownFields::ALL, in_index)
                    .unwrap();
            assert_eq!(readable.address(), expected, "{form:?}");
            assert!(!readable.is_withheld());
        }
        // A root map small enough not to be shrunk is its own published form.
        let small = data_map(7);
        assert_eq!(published_data_map(&small).unwrap(), small);
        assert_eq!(
            PublicForm::UnlistedEnvelope.address(&small).unwrap(),
            EnvelopeOptions::unlisted()
                .envelope(&small, None)
                .unwrap()
                .address()
        );

        // The plain form is the entry's identity, and every form has an
        // address of its own.
        assert_eq!(
            PublicForm::Plain.address(&root).unwrap(),
            data_map_address(&root).unwrap()
        );
        let addresses: BTreeSet<_> = PublicForm::ALL
            .iter()
            .map(|form| form.address(&root).unwrap())
            .collect();
        assert_eq!(addresses.len(), PublicForm::ALL.len());
    }

    /// Compaction writes the address of the form the plan found, never the
    /// plain address for an envelope: nothing is stored there.
    #[test]
    fn apply_compaction_writes_the_planned_address() {
        let unlisted = root_map(8, 0x20);
        let listed = root_map(5, 0x40);
        let plain = data_map(3);
        let private = data_map(4);
        let manifest = Manifest {
            name: None,
            torrent: None,
            entries: vec![
                embedded("unlisted", unlisted.clone()),
                embedded("listed", listed.clone()),
                embedded("plain", plain.clone()),
                embedded("private", private.clone()),
                ManifestEntry {
                    path: Some("public".into()),
                    size: None,
                    source: ContentRef::Public { address: [9; 32] },
                },
            ],
        };
        let entry =
            |index: usize, name: &str, form: Option<PublicForm>, map: &DataMap| EmbeddedEntry {
                index,
                name: name.into(),
                address: match form {
                    Some(form) => form.address(map).unwrap(),
                    None => data_map_address(map).unwrap(),
                },
                form,
            };
        let plan = CompactPlan {
            already_public: vec![
                entry(0, "unlisted", Some(PublicForm::UnlistedEnvelope), &unlisted),
                entry(1, "listed", Some(PublicForm::ListedEnvelope), &listed),
                entry(2, "plain", Some(PublicForm::Plain), &plain),
            ],
            needs_publish: vec![entry(3, "private", None, &private)],
        };
        let compacted = apply_compaction(&manifest, &plan).unwrap();
        let envelope_address = |options: EnvelopeOptions, map: &DataMap| {
            options
                .envelope(&published_data_map(map).unwrap(), None)
                .unwrap()
                .address()
        };
        let unlisted_address = envelope_address(EnvelopeOptions::unlisted(), &unlisted);
        assert_eq!(
            compacted.entries[0].source,
            ContentRef::Public {
                address: unlisted_address
            }
        );
        assert_ne!(unlisted_address, data_map_address(&unlisted).unwrap());
        assert_eq!(
            compacted.entries[1].source,
            ContentRef::Public {
                address: envelope_address(EnvelopeOptions::listed(), &listed)
            }
        );
        assert_eq!(
            compacted.entries[2].source,
            ContentRef::Public {
                address: data_map_address(&plain).unwrap()
            }
        );
        // An entry no address reads stays embedded; an address stays.
        assert_eq!(compacted.entries[3].source, manifest.entries[3].source);
        assert_eq!(
            compacted.entries[4].source,
            ContentRef::Public { address: [9; 32] }
        );
        assert_eq!(compacted.entries[0].path.as_deref(), Some("unlisted"));

        // A plan whose address isn't the one the DataMap gives in its form,
        // or that names no form, is refused.
        let mut wrong = plan.clone();
        wrong.already_public[0].address = data_map_address(&unlisted).unwrap();
        assert!(apply_compaction(&manifest, &wrong).is_err());
        let mut formless = plan.clone();
        formless.already_public[1].form = None;
        assert!(apply_compaction(&manifest, &formless).is_err());
        let mut outside = plan;
        outside.already_public[2].index = 9;
        assert!(apply_compaction(&manifest, &outside).is_err());
    }

    #[test]
    fn plan_helpers() {
        let plan = CompactPlan {
            already_public: vec![EmbeddedEntry {
                index: 0,
                name: "a".into(),
                address: [1; 32],
                form: Some(PublicForm::Plain),
            }],
            needs_publish: vec![EmbeddedEntry {
                index: 2,
                name: "c".into(),
                address: [3; 32],
                form: None,
            }],
        };
        assert!(!plan.is_free());
        assert_eq!(plan.all_indices(), BTreeSet::from([0, 2]));
        assert!(CompactPlan::default().is_free());
    }
}
