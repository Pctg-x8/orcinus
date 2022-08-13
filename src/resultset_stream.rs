use std::task::{Context, Poll};

use futures_util::{future::LocalBoxFuture, FutureExt};
use tokio::io::AsyncReadExt;

use crate::{
    protos::{
        BinaryResultset41, BinaryResultsetRow, CapabilityFlags, ColumnDefinition41, ColumnType,
        EOFPacket41, ErrPacket, Resultset41, ResultsetRow,
    },
    PacketReader,
};

#[derive(Debug)]
pub enum TextResultsetStreamError {
    IO(std::io::Error),
    Described(ErrPacket),
}

pub enum TextResultsetStreamState<'a> {
    Initialized,
    PendingReadOp(LocalBoxFuture<'a, std::io::Result<Resultset41>>),
    Finish { more_resultset: bool },
}
pub struct TextResultsetStream<'s, R> {
    pub stream: &'s mut R,
    pub client_capability: CapabilityFlags,
    pub columns: Vec<ColumnDefinition41>,
    pub state: TextResultsetStreamState<'s>,
}
impl<'s, R> TextResultsetStream<'s, R>
where
    R: PacketReader + Unpin,
{
    pub async fn new(
        stream: &'s mut R,
        column_count: usize,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<TextResultsetStream<'s, R>> {
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            columns.push(
                ColumnDefinition41::read_packet(stream)
                    .await
                    .expect("Failed to read column def"),
            );
        }
        if !client_capability.support_deprecate_eof() {
            EOFPacket41::expected_read_packet(stream)
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
}
impl<R> TextResultsetStream<'_, R> {
    pub fn has_more_resultset(&self) -> Option<bool> {
        match self.state {
            TextResultsetStreamState::Finish { more_resultset } => Some(more_resultset),
            _ => None,
        }
    }
}
impl<'s, R> futures_util::Stream for TextResultsetStream<'s, R>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    type Item = Result<ResultsetRow, TextResultsetStreamError>;

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
                    std::task::Poll::Ready(Err(e)) => {
                        std::task::Poll::Ready(Some(Err(TextResultsetStreamError::IO(e))))
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
                        std::task::Poll::Ready(Some(Err(TextResultsetStreamError::Described(e))))
                    }
                },
                TextResultsetStreamState::Initialized => {
                    let mut f = Resultset41::read_packet(
                        unsafe { &mut *(this.stream as *mut _) as &'s mut _ },
                        this.client_capability,
                    )
                    .boxed_local();

                    match f.poll_unpin(cx) {
                        std::task::Poll::Pending => {
                            this.state = TextResultsetStreamState::PendingReadOp(f);
                            std::task::Poll::Pending
                        }
                        std::task::Poll::Ready(Err(e)) => {
                            std::task::Poll::Ready(Some(Err(TextResultsetStreamError::IO(e))))
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
                        std::task::Poll::Ready(Ok(Resultset41::Err(e))) => std::task::Poll::Ready(
                            Some(Err(TextResultsetStreamError::Described(e))),
                        ),
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

#[derive(Debug)]
pub enum BinaryResultsetStreamError {
    IO(std::io::Error),
    Described(ErrPacket),
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
        stream: &'a mut (impl AsyncReadExt + Unpin),
        client_capabilities: CapabilityFlags,
        column_count: usize,
    ) -> (
        Self,
        Poll<Option<Result<BinaryResultsetRow, BinaryResultsetStreamError>>>,
    ) {
        match self {
            Self::Finish { more_resultset } => (Self::Finish { more_resultset }, Poll::Ready(None)),
            Self::Initialized => {
                let mut f =
                    BinaryResultset41::read_packet(stream, client_capabilities, column_count)
                        .boxed_local();

                match f.poll_unpin(cx) {
                    Poll::Pending => (Self::PendingReadOp(f), Poll::Pending),
                    Poll::Ready(Err(e)) => (
                        Self::Initialized,
                        Poll::Ready(Some(Err(BinaryResultsetStreamError::IO(e)))),
                    ),
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
                        Poll::Ready(Some(Err(BinaryResultsetStreamError::Described(e)))),
                    ),
                }
            }
            Self::PendingReadOp(mut op) => match op.poll_unpin(cx) {
                Poll::Pending => (Self::PendingReadOp(op), Poll::Pending),
                Poll::Ready(Err(e)) => (
                    Self::Initialized,
                    Poll::Ready(Some(Err(BinaryResultsetStreamError::IO(e)))),
                ),
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
                    Poll::Ready(Some(Err(BinaryResultsetStreamError::Described(e)))),
                ),
            },
        }
    }
}
pub struct BinaryResultsetStream<'s, R> {
    pub stream: &'s mut R,
    pub client_capability: CapabilityFlags,
    pub columns: Vec<ColumnDefinition41>,
    pub state: BinaryResultsetStreamState<'s>,
}
impl<'s, R> BinaryResultsetStream<'s, R>
where
    R: PacketReader + Unpin,
{
    pub async fn new(
        stream: &'s mut R,
        client_capability: CapabilityFlags,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetStream<'s, R>> {
        let mut columns = Vec::with_capacity(column_count as _);
        for _ in 0..column_count {
            columns.push(ColumnDefinition41::read_packet(stream).await?);
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
}
impl<R> BinaryResultsetStream<'_, R> {
    pub fn has_more_resultset(&self) -> Option<bool> {
        match self.state {
            BinaryResultsetStreamState::Finish { more_resultset } => Some(more_resultset),
            _ => None,
        }
    }
}
impl<'s, R> futures_util::Stream for BinaryResultsetStream<'s, R>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    type Item = Result<BinaryResultsetRow, BinaryResultsetStreamError>;

    #[inline]
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        let (new_state, poll_result) =
            unsafe { std::ptr::read(&this.state as *const BinaryResultsetStreamState<'s>) }
                .poll_next(
                    cx,
                    unsafe { &mut *(this.stream as *mut _) as &'s mut _ },
                    this.client_capability,
                    this.columns.len(),
                );
        this.state = new_state;
        poll_result
    }
}
