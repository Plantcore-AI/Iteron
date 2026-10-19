//! Bounded diagnostic drain at the process presentation boundary.

pub struct StderrDiagnosticDrain {
    receiver: std::sync::mpsc::Receiver<iteron_kernel::diagnostics::KernelDiagnostic>,
}

impl StderrDiagnosticDrain {
    pub fn channel() -> (iteron_kernel::diagnostics::DiagnosticPort, Self) {
        let (port, receiver) = iteron_kernel::diagnostics::bounded_channel();
        (port, Self { receiver })
    }

    pub fn flush(&self) {
        use std::io::Write as _;

        for diagnostic in self.take() {
            let envelope =
                iteron_kernel::diagnostics::KernelDiagnosticEnvelope::current(diagnostic);
            // Serialization is infallible for the closed, string-free vocabulary. Presentation
            // happens only after the kernel call returns; stderr failure cannot enter its control
            // flow and never redirects a byte onto machine stdout.
            if let Ok(mut line) = serde_json::to_vec(&envelope) {
                line.push(b'\n');
                let _ = std::io::stderr().lock().write_all(&line);
            }
        }
    }

    /// Drain diagnostics that predate frontend attachment into the structured first-paint notice
    /// path. Diagnostics emitted after attachment remain in the same bounded receiver and are
    /// still flushed to stderr when the frontend returns.
    pub fn take(&self) -> Vec<iteron_kernel::diagnostics::KernelDiagnostic> {
        self.receiver.try_iter().collect()
    }
}

impl Drop for StderrDiagnosticDrain {
    fn drop(&mut self) {
        self.flush();
    }
}
