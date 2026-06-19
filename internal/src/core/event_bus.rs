use tokio::sync::broadcast;

pub struct EventBus {
    sender: broadcast::Sender<super::mod_trait::ModuleEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: super::mod_trait::ModuleEvent) -> Result<(), String> {
        // broadcast::send returns Err when there are no receivers; treat that as
        // a benign condition rather than a failure.
        match self.sender.send(event) {
            Ok(_) => Ok(()),
            Err(tokio::sync::broadcast::error::SendError(_)) => Ok(()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<super::mod_trait::ModuleEvent> {
        self.sender.subscribe()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}
