package com.virgilsecurity.crypto;

public class VirgilStreamDataSource extends VirgilDataSource implements java.io.Closeable {
    private java.io.InputStream stream;
    private byte[] buffer;

    public VirgilStreamDataSource(java.io.InputStream stream) {
        this.stream = stream;
    }

    @Override
    public boolean hasData() throws java.io.IOException {
        return this.stream.available() > 0;
    }

    @Override
    public byte[] read() throws java.io.IOException {
        final int bytesToReadNum = Math.min(this.stream.available(), 1024);
        byte[] result = new byte[bytesToReadNum];
        this.stream.read(result, 0, bytesToReadNum);
        return result;
    }

    @Override
    public void close() throws java.io.IOException {
        this.stream.close();
        this.delete();
    }
}
