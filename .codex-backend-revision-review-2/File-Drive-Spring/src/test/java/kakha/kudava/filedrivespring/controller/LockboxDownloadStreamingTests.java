package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.records.LockboxDownloadResult;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

class LockboxDownloadStreamingTests {
    @Test void sharedBufferedResponseStreamsExactBytesAndClosesInput() throws Exception {
        byte[] expected=new byte[LockboxRestController.STREAM_BUFFER_SIZE+17];for(int i=0;i<expected.length;i++)expected[i]=(byte)i;
        TrackingInputStream input=new TrackingInputStream(expected);
        var response=LockboxRestController.downloadResponse(new LockboxDownloadResult("safe.fdcse",expected.length,"application/octet-stream",input));
        ByteArrayOutputStream output=new ByteArrayOutputStream();response.getBody().writeTo(output);
        assertArrayEquals(expected,output.toByteArray());assertTrue(input.closed);assertEquals(expected.length,response.getHeaders().getContentLength());
        assertEquals("no-store",response.getHeaders().getCacheControl());assertTrue(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION).contains("safe.fdcse"));
    }
    @Test void inputClosesWhenClientWriteFails(){
        TrackingInputStream input=new TrackingInputStream(new byte[]{1,2,3});
        var response=LockboxRestController.downloadResponse(new LockboxDownloadResult("safe.fdcse",3,"application/octet-stream",input));
        OutputStream failed=new OutputStream(){public void write(int value)throws IOException{throw new IOException("disconnect");}public void write(byte[] b,int o,int l)throws IOException{throw new IOException("disconnect");}};
        assertThrows(IOException.class,()->response.getBody().writeTo(failed));assertTrue(input.closed);
    }
    private static final class TrackingInputStream extends ByteArrayInputStream{boolean closed;TrackingInputStream(byte[] data){super(data);}@Override public void close()throws IOException{closed=true;super.close();}}
}
