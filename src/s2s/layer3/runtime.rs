pub trait Layer3ReplicationRuntime<S, T> {
    type Command;
    type Frame;

    fn propose_local(
        &mut self,
        command: Self::Command,
        storage: &mut S,
        transport: &T,
    ) -> Result<Self::Frame, String>;

    fn ingest_remote(
        &mut self,
        frame: Self::Frame,
        storage: &mut S,
    ) -> Result<bool, String>;

    fn catch_up_with_overlay(&mut self, storage: &mut S, transport: &T) -> Result<usize, String>;
}
