package kakha.kudava.fdclient.service;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WindowsWebAuthnLayoutTest {
    @Test void versionOneWindowsStructuresHaveSdkLayoutOn64Bit() {
        if (Native.POINTER_SIZE != 8) return;
        assertEquals(24, new WindowsWebAuthn.ClientData().size());
        assertEquals(24, new WindowsWebAuthn.Credential().size());
        assertEquals(56, new WindowsWebAuthn.AssertionOptions().size());
        Memory empty = new Memory(72);
        empty.clear();
        assertEquals(72, new WindowsWebAuthn.Assertion(empty).size());
    }

    @Test void windowsApiIsCallable() {
        if (System.getProperty("os.name", "").toLowerCase().contains("win"))
            assertTrue(WindowsWebAuthn.windowsApiVersion() >= 1);
    }
}
