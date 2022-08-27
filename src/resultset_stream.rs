//! Lazily resultset fetching providers.

use std::{
    io::Read,
    task::{Context, Poll},
};

use futures_util::{future::BoxFuture, FutureExt, TryStreamExt};
use tokio::io::AsyncRead;

use crate::{
    protos::{
        AsyncReceivePacket, BinaryResultset41, BinaryResultsetRow, CapabilityFlags,
        ColumnDefinition41, ColumnType, EOFPacket41, ReceivePacket, Resultset41, ResultsetRow,
    },
    CommunicationError,
};

/// Blocking fetch of resultsets.
pub enum TextResultsetIterationState {
    AwaitingNext,
    Finished { more_resultset: bool },
}
impl Default for TextResultsetIterationState {
    fn default() -> Self {
        Self::INIT
    }
}
impl TextResultsetIterationState {
    /// Initial State
    pub const INIT: Self = Self::AwaitingNext;

    /// Fetches next resultset.
    pub fn next(
        &mut self,
        stream: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
    ) -> Option<Result<ResultsetRow, CommunicationError>> {
        match self {
            Self::Finished { .. } => None,
            this @ Self::AwaitingNext => {
                match Resultset41::read_packet_sync(stream, client_capability) {
                    Err(e) => Some(Err(e.into())),
                    Ok(Resultset41::Row(r)) => Some(Ok(r)),
                    Ok(Resultset41::Ok(k)) => {
                        *this = Self::Finished {
                            more_resultset: k
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        };

                        None
                    }
                    Ok(Resultset41::EOF(e)) => {
                        *this = Self::Finished {
                            more_resultset: e.status_flags.more_result_exists(),
                        };

                        None
                    }
                    Ok(Resultset41::Err(e)) => Some(Err(e.into())),
                }
            }
        }
    }
}

/// An iterator wrapping `TextResultsetIterationState`
pub struct TextResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    stream: R,
    client_capability: CapabilityFlags,
    columns: Vec<ColumnDefinition41>,
    state: TextResultsetIterationState,
}
impl<R> TextResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    /// Initializes the iterator, reading first column information packets.
    pub fn new(
        mut stream: R,
        column_count: usize,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            columns.push(ColumnDefinition41::read_packet(
                &mut *stream,
                client_capability,
            )?);
        }
        if !client_capability.support_deprecate_eof() {
            EOFPacket41::expected_read_packet_sync(&mut *stream)?;
        }

        Ok(Self {
            stream,
            client_capability,
            columns,
            state: TextResultsetIterationState::INIT,
        })
    }

    /// Column informations of this resultset.
    #[inline]
    pub fn columns(&self) -> &[ColumnDefinition41] {
        &self.columns
    }

    /// Returns whether last operation has more resultsets after this iteration.
    pub fn has_more_resultset(&self) -> bool {
        match self.state {
            TextResultsetIterationState::Finished { more_resultset } => more_resultset,
            _ => false,
        }
    }

    /// Discards all resultset rows.
    pub fn drop_all_rows(&mut self) -> Result<(), CommunicationError> {
        while let Some(r) = self.next() {
            let _ = r?;
        }

        Ok(())
    }
}
impl<R> Iterator for TextResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    type Item = Result<ResultsetRow, CommunicationError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.state.next(&mut *self.stream, self.client_capability)
    }
}

/// Non-blocking fetch of resultsets.
pub enum TextResultsetStreamState<'a> {
    Initialized,
    PendingReadOp(BoxFuture<'a, std::io::Result<Resultset41>>),
    Finish { more_resultset: bool },
}
impl Default for TextResultsetStreamState<'_> {
    fn default() -> Self {
        Self::INIT
    }
}
impl<'a> TextResultsetStreamState<'a> {
    /// Initial State
    pub const INIT: Self = Self::Initialized;

    /// Fetches next resultset.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
        stream: &'a mut (impl AsyncRead + Send + Sync + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
    ) -> Poll<Option<Result<ResultsetRow, CommunicationError>>> {
        match self {
            Self::Finish { .. } => Poll::Ready(None),
            this @ Self::Initialized => {
                let mut f = Resultset41::read_packet(stream, client_capabilities).boxed();

                match f.poll_unpin(cx) {
                    Poll::Pending => {
                        *this = Self::PendingReadOp(f);

                        Poll::Pending
                    }
                    Poll::Ready(Err(e)) => {
                        *this = Self::Initialized;

                        Poll::Ready(Some(Err(e.into())))
                    }
                    Poll::Ready(Ok(Resultset41::Row(r))) => {
                        *this = Self::Initialized;
                        Poll::Ready(Some(Ok(r)))
                    }
                    Poll::Ready(Ok(Resultset41::Ok(o))) => {
                        *this = Self::Finish {
                            more_resultset: o
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        };

                        Poll::Ready(None)
                    }
                    Poll::Ready(Ok(Resultset41::EOF(e))) => {
                        *this = Self::Finish {
                            more_resultset: e.status_flags.more_result_exists(),
                        };

                        Poll::Ready(None)
                    }
                    Poll::Ready(Ok(Resultset41::Err(e))) => {
                        *this = Self::Finish {
                            more_resultset: false,
                        };

                        Poll::Ready(Some(Err(e.into())))
                    }
                }
            }
            Self::PendingReadOp(ref mut op) => match op.poll_unpin(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => {
                    *self = Self::Initialized;

                    Poll::Ready(Some(Err(e.into())))
                }
                Poll::Ready(Ok(Resultset41::Row(r))) => {
                    *self = Self::Initialized;

                    Poll::Ready(Some(Ok(r)))
                }
                Poll::Ready(Ok(Resultset41::Ok(o))) => {
                    *self = Self::Finish {
                        more_resultset: o.status_flags().unwrap_or_default().more_result_exists(),
                    };

                    Poll::Ready(None)
                }
                Poll::Ready(Ok(Resultset41::EOF(e))) => {
                    *self = Self::Finish {
                        more_resultset: e.status_flags.more_result_exists(),
                    };

                    Poll::Ready(None)
                }
                Poll::Ready(Ok(Resultset41::Err(e))) => {
                    *self = Self::Finish {
                        more_resultset: false,
                    };

                    Poll::Ready(Some(Err(e.into())))
                }
            },
        }
    }
}

/// An stream wrapping `TextResultsetStreamState`
pub struct TextResultsetStream<'s, R: ?Sized> {
    stream: &'s mut R,
    client_capability: CapabilityFlags,
    columns: Vec<ColumnDefinition41>,
    state: TextResultsetStreamState<'s>,
}
impl<'s, R> TextResultsetStream<'s, R>
where
    R: AsyncRead + Send + Sync + Unpin + ?Sized,
{
    /// Initializes the iterator, reading first column information packets.
    pub async fn new(
        mut stream: &'s mut R,
        column_count: usize,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<TextResultsetStream<'s, R>> {
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            columns.push(
                ColumnDefinition41::read_packet_async(&mut stream, client_capability)
                    .await
                    .expect("Failed to read column def"),
            );
        }
        if !client_capability.support_deprecate_eof() {
            EOFPacket41::expected_read_packet(&mut stream)
                .await
                .expect("Failed to read eof packet of columns");
        }

        Ok(Self {
            stream,
            client_capability,
            columns,
            state: TextResultsetStreamState::Initialized,
        })
    }

    /// Discards all resultset rows.
    pub async fn drop_all_rows(&mut self) -> Result<(), CommunicationError> {
        while let Some(_) = self.try_next().await? {}

        Ok(())
    }
}
impl<R: ?Sized> TextResultsetStream<'_, R> {
    /// Column informations of this resultset.
    #[inline]
    pub fn columns(&self) -> &[ColumnDefinition41] {
        &self.columns
    }

    /// Types of column.
    ///
    /// This function does not check whether returned type byte is valid.
    #[inline]
    pub unsafe fn column_types_unchecked<'s>(&'s self) -> impl Iterator<Item = ColumnType> + 's {
        self.columns.iter().map(|c| c.type_unchecked())
    }

    /// Returns whether last operation has more resultsets after this iteration.
    pub fn has_more_resultset(&self) -> Option<bool> {
        match self.state {
            TextResultsetStreamState::Finish { more_resultset } => Some(more_resultset),
            _ => None,
        }
    }
}
impl<'s, R> futures_util::Stream for TextResultsetStream<'s, R>
where
    R: AsyncRead + Unpin + Send + Sync + ?Sized,
{
    type Item = Result<ResultsetRow, CommunicationError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        this.state.poll_next(
            cx,
            unsafe { &mut *(this.stream as *mut _) as &'s mut _ },
            this.client_capability,
        )
    }
}

/// Blocking fetch of binary protocol resultsets.
pub enum BinaryResultsetIterationState {
    AwaitingNext,
    Finished { more_resultset: bool },
}
impl Default for BinaryResultsetIterationState {
    fn default() -> Self {
        Self::INIT
    }
}
impl BinaryResultsetIterationState {
    /// Initial State
    pub const INIT: Self = Self::AwaitingNext;

    /// Fetches next resultset.
    pub fn next(
        &mut self,
        stream: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
        column_count: usize,
    ) -> Option<Result<BinaryResultsetRow, CommunicationError>> {
        match self {
            Self::Finished { .. } => None,
            this @ Self::AwaitingNext => {
                match BinaryResultset41::read_packet_sync(stream, client_capability, column_count) {
                    Err(e) => Some(Err(e.into())),
                    Ok(BinaryResultset41::Row(r)) => Some(Ok(r)),
                    Ok(BinaryResultset41::Ok(k)) => {
                        *this = Self::Finished {
                            more_resultset: k
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        };

                        None
                    }
                    Ok(BinaryResultset41::EOF(e)) => {
                        *this = Self::Finished {
                            more_resultset: e.status_flags.more_result_exists(),
                        };

                        None
                    }
                    Ok(BinaryResultset41::Err(e)) => Some(Err(e.into())),
                }
            }
        }
    }
}

/// An iterator wrapping `BinaryResultsetIterationState`
pub struct BinaryResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    stream: R,
    client_capability: CapabilityFlags,
    columns: Vec<ColumnDefinition41>,
    state: BinaryResultsetIterationState,
}
impl<R> BinaryResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    /// Initializes the iterator, reading first column information packets.
    pub fn new(
        mut stream: R,
        column_count: usize,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            columns.push(ColumnDefinition41::read_packet(
                &mut *stream,
                client_capability,
            )?);
        }
        if !client_capability.support_deprecate_eof() {
            EOFPacket41::expected_read_packet_sync(&mut *stream)?;
        }

        Ok(Self {
            stream,
            client_capability,
            columns,
            state: BinaryResultsetIterationState::INIT,
        })
    }

    /// Column informations of this resultset.
    #[inline]
    pub fn columns(&self) -> &[ColumnDefinition41] {
        &self.columns
    }

    /// Types of column.
    ///
    /// This function does not check whether returned type byte is valid.
    #[inline]
    pub unsafe fn column_types_unchecked<'s>(&'s self) -> impl Iterator<Item = ColumnType> + 's {
        self.columns.iter().map(|c| c.type_unchecked())
    }

    /// Returns whether last operation has more resultsets after this iteration.
    pub fn has_more_resultset(&self) -> bool {
        match self.state {
            BinaryResultsetIterationState::Finished { more_resultset } => more_resultset,
            _ => false,
        }
    }

    /// Discards all resultset rows.
    pub fn drop_all_rows(&mut self) -> Result<(), CommunicationError> {
        while let Some(r) = self.next() {
            let _ = r?;
        }

        Ok(())
    }
}
impl<R> Iterator for BinaryResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    type Item = Result<BinaryResultsetRow, CommunicationError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.state.next(
            &mut *self.stream,
            self.client_capability,
            self.columns.len(),
        )
    }
}

/// Non-blocking fetch of binary protocol resultsets.
pub enum BinaryResultsetStreamState<'a> {
    Initialized,
    PendingReadOp(BoxFuture<'a, std::io::Result<BinaryResultset41>>),
    Finish { more_resultset: bool },
}
impl Default for BinaryResultsetStreamState<'_> {
    fn default() -> Self {
        Self::INIT
    }
}
impl<'a> BinaryResultsetStreamState<'a> {
    /// Initial State
    pub const INIT: Self = Self::Initialized;

    /// Fetches next resultset.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
        stream: &'a mut (impl AsyncRead + Send + Sync + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
        column_count: usize,
    ) -> Poll<Option<Result<BinaryResultsetRow, CommunicationError>>> {
        match self {
            Self::Finish { .. } => Poll::Ready(None),
            this @ Self::Initialized => {
                let mut f =
                    BinaryResultset41::read_packet(stream, client_capabilities, column_count)
                        .boxed();

                match f.poll_unpin(cx) {
                    Poll::Pending => {
                        *this = Self::PendingReadOp(f);

                        Poll::Pending
                    }
                    Poll::Ready(Err(e)) => {
                        *this = Self::Initialized;

                        Poll::Ready(Some(Err(e.into())))
                    }
                    Poll::Ready(Ok(BinaryResultset41::Row(r))) => {
                        *this = Self::Initialized;
                        Poll::Ready(Some(Ok(r)))
                    }
                    Poll::Ready(Ok(BinaryResultset41::Ok(o))) => {
                        *this = Self::Finish {
                            more_resultset: o
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        };

                        Poll::Ready(None)
                    }
                    Poll::Ready(Ok(BinaryResultset41::EOF(e))) => {
                        *this = Self::Finish {
                            more_resultset: e.status_flags.more_result_exists(),
                        };

                        Poll::Ready(None)
                    }
                    Poll::Ready(Ok(BinaryResultset41::Err(e))) => {
                        *this = Self::Finish {
                            more_resultset: false,
                        };

                        Poll::Ready(Some(Err(e.into())))
                    }
                }
            }
            Self::PendingReadOp(ref mut op) => match op.poll_unpin(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => {
                    *self = Self::Initialized;

                    Poll::Ready(Some(Err(e.into())))
                }
                Poll::Ready(Ok(BinaryResultset41::Row(r))) => {
                    *self = Self::Initialized;

                    Poll::Ready(Some(Ok(r)))
                }
                Poll::Ready(Ok(BinaryResultset41::Ok(o))) => {
                    *self = Self::Finish {
                        more_resultset: o.status_flags().unwrap_or_default().more_result_exists(),
                    };

                    Poll::Ready(None)
                }
                Poll::Ready(Ok(BinaryResultset41::EOF(e))) => {
                    *self = Self::Finish {
                        more_resultset: e.status_flags.more_result_exists(),
                    };

                    Poll::Ready(None)
                }
                Poll::Ready(Ok(BinaryResultset41::Err(e))) => {
                    *self = Self::Finish {
                        more_resultset: false,
                    };

                    Poll::Ready(Some(Err(e.into())))
                }
            },
        }
    }
}

/// An stream wrapping `BinaryResultsetStreamState`
pub struct BinaryResultsetStream<'s, R: ?Sized> {
    stream: &'s mut R,
    client_capability: CapabilityFlags,
    columns: Vec<ColumnDefinition41>,
    state: BinaryResultsetStreamState<'s>,
}
impl<'s, R> BinaryResultsetStream<'s, R>
where
    R: AsyncRead + Send + Sync + Unpin + ?Sized,
{
    /// Initializes the iterator, reading first column information packets.
    pub async fn new(
        mut stream: &'s mut R,
        client_capability: CapabilityFlags,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetStream<'s, R>> {
        let mut columns = Vec::with_capacity(column_count as _);
        for _ in 0..column_count {
            columns
                .push(ColumnDefinition41::read_packet_async(&mut stream, client_capability).await?);
        }

        Ok(Self {
            stream,
            client_capability,
            columns,
            state: BinaryResultsetStreamState::Initialized,
        })
    }

    /// Discards all resultset rows.
    pub async fn drop_all_rows(&mut self) -> Result<(), CommunicationError> {
        while let Some(_) = self.try_next().await? {}

        Ok(())
    }
}
impl<R: ?Sized> BinaryResultsetStream<'_, R> {
    /// Column informations of this resultset.
    #[inline]
    pub fn columns(&self) -> &[ColumnDefinition41] {
        &self.columns
    }

    /// Types of column.
    ///
    /// This function does not check whether returned type byte is valid.
    #[inline]
    pub unsafe fn column_types_unchecked<'s>(&'s self) -> impl Iterator<Item = ColumnType> + 's {
        self.columns.iter().map(|c| c.type_unchecked())
    }

    /// Returns whether last operation has more resultsets after this iteration.
    pub fn has_more_resultset(&self) -> Option<bool> {
        match self.state {
            BinaryResultsetStreamState::Finish { more_resultset } => Some(more_resultset),
            _ => None,
        }
    }
}
impl<'s, R> futures_util::Stream for BinaryResultsetStream<'s, R>
where
    R: AsyncRead + Send + Sync + Unpin + ?Sized,
{
    type Item = Result<BinaryResultsetRow, CommunicationError>;

    #[inline]
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        this.state.poll_next(
            cx,
            unsafe { &mut *(this.stream as *mut _) as &'s mut _ },
            this.client_capability,
            this.columns.len(),
        )
    }
}
