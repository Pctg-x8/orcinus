use std::{
    io::Read,
    task::{Context, Poll},
};

use futures_util::{
    future::{BoxFuture, LocalBoxFuture},
    FutureExt, TryStreamExt,
};
use tokio::io::AsyncRead;

use crate::{
    protos::{
        AsyncReceivePacket, BinaryResultset41, BinaryResultsetRow, CapabilityFlags,
        ColumnDefinition41, ColumnType, EOFPacket41, ReceivePacket, Resultset41, ResultsetRow,
    },
    CommunicationError,
};

pub enum TextResultsetIteratorState {
    AwaitingNext,
    Finished { more_resultset: bool },
}
impl TextResultsetIteratorState {
    pub fn next(
        self,
        stream: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
    ) -> (Self, Option<Result<ResultsetRow, CommunicationError>>) {
        match self {
            Self::Finished { .. } => (self, None),
            Self::AwaitingNext => match Resultset41::read_packet_sync(stream, client_capability) {
                Err(e) => (self, Some(Err(e.into()))),
                Ok(Resultset41::Row(r)) => (self, Some(Ok(r))),
                Ok(Resultset41::Ok(k)) => (
                    Self::Finished {
                        more_resultset: k.status_flags().unwrap_or_default().more_result_exists(),
                    },
                    None,
                ),
                Ok(Resultset41::EOF(e)) => (
                    Self::Finished {
                        more_resultset: e.status_flags.more_result_exists(),
                    },
                    None,
                ),
                Ok(Resultset41::Err(e)) => (self, Some(Err(e.into()))),
            },
        }
    }
}
pub struct TextResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    pub stream: R,
    pub client_capability: CapabilityFlags,
    pub columns: Vec<ColumnDefinition41>,
    pub state: TextResultsetIteratorState,
}
impl<R> TextResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
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
            state: TextResultsetIteratorState::AwaitingNext,
        })
    }

    pub fn has_more_resultset(&self) -> bool {
        match self.state {
            TextResultsetIteratorState::Finished { more_resultset } => more_resultset,
            _ => false,
        }
    }

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
        let (new_state, res) =
            unsafe { std::ptr::read(&self.state) }.next(&mut *self.stream, self.client_capability);
        self.state = new_state;
        res
    }
}

pub enum TextResultsetStreamState<'a> {
    Initialized,
    PendingReadOp(BoxFuture<'a, std::io::Result<Resultset41>>),
    Finish { more_resultset: bool },
}
pub struct TextResultsetStream<'s, R: ?Sized> {
    pub stream: &'s mut R,
    pub client_capability: CapabilityFlags,
    pub columns: Vec<ColumnDefinition41>,
    pub state: TextResultsetStreamState<'s>,
}
impl<'s, R> TextResultsetStream<'s, R>
where
    R: AsyncRead + Send + Sync + Unpin + ?Sized,
{
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

    pub async fn drop_all_rows(&mut self) -> Result<(), CommunicationError> {
        while let Some(_) = self.try_next().await? {}

        Ok(())
    }
}
impl<R: ?Sized> TextResultsetStream<'_, R> {
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

        if let TextResultsetStreamState::Finish { .. } = this.state {
            std::task::Poll::Ready(None)
        } else {
            match std::mem::replace(&mut this.state, TextResultsetStreamState::Initialized) {
                TextResultsetStreamState::PendingReadOp(mut op) => match op.poll_unpin(cx) {
                    std::task::Poll::Pending => {
                        this.state = TextResultsetStreamState::PendingReadOp(op);
                        std::task::Poll::Pending
                    }
                    std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Some(Err(e.into()))),
                    std::task::Poll::Ready(Ok(Resultset41::Row(r))) => {
                        std::task::Poll::Ready(Some(Ok(r)))
                    }
                    std::task::Poll::Ready(Ok(Resultset41::Ok(o))) => {
                        this.state = TextResultsetStreamState::Finish {
                            more_resultset: o
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        };
                        std::task::Poll::Ready(None)
                    }
                    std::task::Poll::Ready(Ok(Resultset41::EOF(o))) => {
                        this.state = TextResultsetStreamState::Finish {
                            more_resultset: o.status_flags.more_result_exists(),
                        };
                        std::task::Poll::Ready(None)
                    }
                    std::task::Poll::Ready(Ok(Resultset41::Err(e))) => {
                        std::task::Poll::Ready(Some(Err(e.into())))
                    }
                },
                TextResultsetStreamState::Initialized => {
                    let mut f = Resultset41::read_packet(
                        unsafe { &mut *(this.stream as *mut _) as &'s mut _ },
                        this.client_capability,
                    )
                    .boxed();

                    match f.poll_unpin(cx) {
                        std::task::Poll::Pending => {
                            this.state = TextResultsetStreamState::PendingReadOp(f);
                            std::task::Poll::Pending
                        }
                        std::task::Poll::Ready(Err(e)) => {
                            std::task::Poll::Ready(Some(Err(e.into())))
                        }
                        std::task::Poll::Ready(Ok(Resultset41::Row(r))) => {
                            std::task::Poll::Ready(Some(Ok(r)))
                        }
                        std::task::Poll::Ready(Ok(Resultset41::Ok(o))) => {
                            this.state = TextResultsetStreamState::Finish {
                                more_resultset: o
                                    .status_flags()
                                    .unwrap_or_default()
                                    .more_result_exists(),
                            };
                            std::task::Poll::Ready(None)
                        }
                        std::task::Poll::Ready(Ok(Resultset41::EOF(o))) => {
                            this.state = TextResultsetStreamState::Finish {
                                more_resultset: o.status_flags.more_result_exists(),
                            };
                            std::task::Poll::Ready(None)
                        }
                        std::task::Poll::Ready(Ok(Resultset41::Err(e))) => {
                            std::task::Poll::Ready(Some(Err(e.into())))
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

pub enum BinaryResultsetIteratorState {
    AwaitingNext,
    Finished { more_resultset: bool },
}
impl BinaryResultsetIteratorState {
    pub fn next(
        self,
        stream: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
        column_count: usize,
    ) -> (Self, Option<Result<BinaryResultsetRow, CommunicationError>>) {
        match self {
            Self::Finished { .. } => (self, None),
            Self::AwaitingNext => {
                match BinaryResultset41::read_packet_sync(stream, client_capability, column_count) {
                    Err(e) => (self, Some(Err(e.into()))),
                    Ok(BinaryResultset41::Row(r)) => (self, Some(Ok(r))),
                    Ok(BinaryResultset41::Ok(k)) => (
                        Self::Finished {
                            more_resultset: k
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        },
                        None,
                    ),
                    Ok(BinaryResultset41::EOF(e)) => (
                        Self::Finished {
                            more_resultset: e.status_flags.more_result_exists(),
                        },
                        None,
                    ),
                    Ok(BinaryResultset41::Err(e)) => (self, Some(Err(e.into()))),
                }
            }
        }
    }
}
pub struct BinaryResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
    pub stream: R,
    pub client_capability: CapabilityFlags,
    pub columns: Vec<ColumnDefinition41>,
    pub state: BinaryResultsetIteratorState,
}
impl<R> BinaryResultsetIterator<R>
where
    R: std::ops::DerefMut,
    R::Target: Read,
{
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
            state: BinaryResultsetIteratorState::AwaitingNext,
        })
    }

    pub fn has_more_resultset(&self) -> bool {
        match self.state {
            BinaryResultsetIteratorState::Finished { more_resultset } => more_resultset,
            _ => false,
        }
    }

    pub unsafe fn column_types_unchecked<'s>(&'s self) -> impl Iterator<Item = ColumnType> + 's {
        self.columns.iter().map(|c| c.type_unchecked())
    }

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
        let (new_state, res) = unsafe { std::ptr::read(&self.state) }.next(
            &mut *self.stream,
            self.client_capability,
            self.columns.len(),
        );
        self.state = new_state;
        res
    }
}

pub enum BinaryResultsetStreamState<'a> {
    Initialized,
    PendingReadOp(LocalBoxFuture<'a, std::io::Result<BinaryResultset41>>),
    Finish { more_resultset: bool },
}
impl<'a> BinaryResultsetStreamState<'a> {
    pub fn poll_next(
        self,
        cx: &mut Context<'_>,
        stream: &'a mut (impl AsyncRead + Send + Sync + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
        column_count: usize,
    ) -> (
        Self,
        Poll<Option<Result<BinaryResultsetRow, CommunicationError>>>,
    ) {
        match self {
            Self::Finish { more_resultset } => (Self::Finish { more_resultset }, Poll::Ready(None)),
            Self::Initialized => {
                let mut f =
                    BinaryResultset41::read_packet(stream, client_capabilities, column_count)
                        .boxed_local();

                match f.poll_unpin(cx) {
                    Poll::Pending => (Self::PendingReadOp(f), Poll::Pending),
                    Poll::Ready(Err(e)) => (Self::Initialized, Poll::Ready(Some(Err(e.into())))),
                    Poll::Ready(Ok(BinaryResultset41::Row(r))) => {
                        (Self::Initialized, Poll::Ready(Some(Ok(r))))
                    }
                    Poll::Ready(Ok(BinaryResultset41::Ok(o))) => (
                        Self::Finish {
                            more_resultset: o
                                .status_flags()
                                .unwrap_or_default()
                                .more_result_exists(),
                        },
                        Poll::Ready(None),
                    ),
                    Poll::Ready(Ok(BinaryResultset41::EOF(e))) => (
                        Self::Finish {
                            more_resultset: e.status_flags.more_result_exists(),
                        },
                        Poll::Ready(None),
                    ),
                    Poll::Ready(Ok(BinaryResultset41::Err(e))) => (
                        Self::Finish {
                            more_resultset: false,
                        },
                        Poll::Ready(Some(Err(e.into()))),
                    ),
                }
            }
            Self::PendingReadOp(mut op) => match op.poll_unpin(cx) {
                Poll::Pending => (Self::PendingReadOp(op), Poll::Pending),
                Poll::Ready(Err(e)) => (Self::Initialized, Poll::Ready(Some(Err(e.into())))),
                Poll::Ready(Ok(BinaryResultset41::Row(r))) => {
                    (Self::Initialized, Poll::Ready(Some(Ok(r))))
                }
                Poll::Ready(Ok(BinaryResultset41::Ok(o))) => (
                    Self::Finish {
                        more_resultset: o.status_flags().unwrap_or_default().more_result_exists(),
                    },
                    Poll::Ready(None),
                ),
                Poll::Ready(Ok(BinaryResultset41::EOF(e))) => (
                    Self::Finish {
                        more_resultset: e.status_flags.more_result_exists(),
                    },
                    Poll::Ready(None),
                ),
                Poll::Ready(Ok(BinaryResultset41::Err(e))) => (
                    Self::Finish {
                        more_resultset: false,
                    },
                    Poll::Ready(Some(Err(e.into()))),
                ),
            },
        }
    }
}
pub struct BinaryResultsetStream<'s, R: ?Sized> {
    pub stream: &'s mut R,
    pub client_capability: CapabilityFlags,
    pub columns: Vec<ColumnDefinition41>,
    pub state: BinaryResultsetStreamState<'s>,
}
impl<'s, R> BinaryResultsetStream<'s, R>
where
    R: AsyncRead + Send + Sync + Unpin + ?Sized,
{
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

    pub unsafe fn column_types_unchecked(&'s self) -> impl Iterator<Item = ColumnType> + 's {
        self.columns.iter().map(|c| c.type_unchecked())
    }

    pub async fn drop_all_rows(&mut self) -> Result<(), CommunicationError> {
        while let Some(_) = self.try_next().await? {}

        Ok(())
    }
}
impl<R: ?Sized> BinaryResultsetStream<'_, R> {
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

        let (new_state, poll_result) = unsafe { std::ptr::read(&this.state) }.poll_next(
            cx,
            unsafe { &mut *(this.stream as *mut _) as &'s mut _ },
            this.client_capability,
            this.columns.len(),
        );
        this.state = new_state;
        poll_result
    }
}
