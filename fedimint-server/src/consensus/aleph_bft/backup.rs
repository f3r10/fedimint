use async_trait::async_trait;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;
use tracing::info;

use crate::consensus::db::{AlephUnitsKey, AlephUnitsPrefix};
use crate::LOG_CONSENSUS;

pub struct BackupReader {
    db: Database,
}

impl BackupReader {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait]
impl aleph_bft::BackupReader for BackupReader {
    async fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut dbtx = self.db.begin_transaction_nc().await;

        let units = dbtx
            .find_by_prefix(&AlephUnitsPrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<Vec<u8>>>()
            .await;

        if !units.is_empty() {
            info!(target: LOG_CONSENSUS, units_len = %units.len(), "Recovering from an in-session-shutdown");
        }

        Ok(units.into_iter().flatten().collect())
    }
}

pub struct BackupWriter {
    db: Database,
    units_index: u64,
}

impl BackupWriter {
    pub async fn new(db: Database) -> Self {
        let units_index = db
            .begin_transaction_nc()
            .await
            .find_by_prefix_sorted_descending(&AlephUnitsPrefix)
            .await
            .next()
            .await
            .map_or(0, |entry| (entry.0 .0) + 1);

        Self { db, units_index }
    }
}

#[async_trait]
impl aleph_bft::BackupWriter for BackupWriter {
    async fn append(&mut self, data: &[u8]) -> std::io::Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        dbtx.insert_new_entry(&AlephUnitsKey(self.units_index), &data.to_owned())
            .await;

        self.units_index += 1;

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");

        Ok(())
    }
}
