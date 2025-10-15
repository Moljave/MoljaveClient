using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    internal sealed class TlsClientTransportStream : Stream
    {
        private readonly TlsClient _client;
        private readonly Stream _innerStream;
        private bool _disposed;

        public TlsClientTransportStream(TlsClient client, Stream innerStream)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        }

        public override bool CanRead => _innerStream.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _innerStream.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => _innerStream.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => _innerStream.Write(buffer, offset, count);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                _innerStream.Dispose();
                _client.Dispose();
            }

            _disposed = true;
            base.Dispose(disposing);
        }
    }
}

