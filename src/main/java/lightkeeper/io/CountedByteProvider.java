package lightkeeper.io;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;

public class CountedByteProvider implements ByteProvider {
	private InputStream inputStream;
	private long length;
	private long currentIndex;

	public CountedByteProvider(InputStream inputStream, long length) {
		this.inputStream = inputStream;
		this.length = length;
	}

	@Override
	public void close() {
		// don't do anything for now
	}

	@Override
	public File getFile() {
		return null;
	}

	public InputStream getUnderlyingInputStream() {
		return inputStream;
	}
	
	public long getPosition() {
		return this.currentIndex;
	}
	
	public long getLength() {
		return this.length;
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		return "InputStreamByteProvider Index=0x" + Long.toHexString(currentIndex) + " Length=0x" +
				Long.toHexString(length);
	}

	@Override
	public String getAbsolutePath() {
		return getName();
	}

	@Override
	public long length() throws IOException {
		return length;
	}

	@Override
	public boolean isValidIndex(long index) {
		return (index >= 0L) && (index < length);
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (index < currentIndex) {
			throw new IOException("Attempted to read byte that was already read.");
		}
		else if (index > currentIndex) {
			currentIndex += inputStream.skip(index - currentIndex);
			if (currentIndex != index) {
				throw new IOException("Not enough bytes were skipped.");
			}
		}

		int value = inputStream.read();
		if (value == -1) {
			throw new EOFException();
		}
		currentIndex += 1L;
		return (byte) value;
	}

	@Override
	public byte[] readBytes(long index, long len) throws IOException {
		if (index < currentIndex) {
			throw new IOException("Attempted to read bytes that were already read.");
		}
		else if (index > currentIndex) {
			currentIndex += inputStream.skip(index - currentIndex);
			if (currentIndex != index) {
				throw new IOException("Not enough bytes were skipped.");
			}
		}

		byte[] values = new byte[(int) len];
		int nRead = inputStream.read(values);
		if (nRead != len) {
			throw new EOFException();
		}
		currentIndex += len;
		return values;
	}
}
