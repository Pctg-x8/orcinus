use std::{io::Read, pin::Pin, sync::atomic::AtomicUsize, task::Poll};

use tokio::io::AsyncRead;

pub struct ReadCounted<R> {
    inner: R,
    counter: AtomicUsize,
}
impl<R> ReadCounted<R> {
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            counter: AtomicUsize::new(0),
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn read_bytes(&self) -> usize {
        self.counter.load(std::sync::atomic::Ordering::Acquire)
    }
}
impl<R> AsyncRead for ReadCounted<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        match unsafe { Pin::new_unchecked(&mut this.inner).poll_read(cx, buf) } {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                this.counter
                    .fetch_add(buf.filled().len(), std::sync::atomic::Ordering::AcqRel);
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl<R> Read for ReadCounted<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = R::read(&mut self.inner, buf)?;
        self.counter
            .fetch_add(bytes, std::sync::atomic::Ordering::AcqRel);
        Ok(bytes)
    }
}

pub struct ReadCountedSync<R> {
    inner: R,
    counter: usize,
}
impl<R> ReadCountedSync<R> {
    pub const fn new(inner: R) -> Self {
        Self { inner, counter: 0 }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn read_bytes(&self) -> usize {
        self.counter
    }
}
impl<R> Read for ReadCountedSync<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = R::read(&mut self.inner, buf)?;
        self.counter += bytes;
        Ok(bytes)
    }
}
