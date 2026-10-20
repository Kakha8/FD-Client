package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Windows WebAuthn assertion bridge. All native calls run off the JavaFX thread. */
public final class WindowsWebAuthn {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private interface Api extends StdCallLibrary {
        int WebAuthNGetApiVersionNumber();
        int WebAuthNAuthenticatorGetAssertion(Pointer window, WString rpId, ClientData clientData,
                                              AssertionOptions options, PointerByReference assertion);
        void WebAuthNFreeAssertion(Pointer assertion);
        Pointer WebAuthNGetErrorName(int result);
    }

    private interface Windows extends StdCallLibrary {
        Pointer GetForegroundWindow();
        Pointer GetTopWindow(Pointer parent);
    }

    @Structure.FieldOrder({"version", "length", "data", "algorithm"})
    public static class ClientData extends Structure {
        public int version, length;
        public Pointer data;
        public WString algorithm;
    }

    @Structure.FieldOrder({"version", "length", "id", "type"})
    public static class Credential extends Structure {
        public int version, length;
        public Pointer id;
        public WString type;
        public Credential() { super(); }
        public Credential(Pointer pointer) { super(pointer); read(); }
    }

    @Structure.FieldOrder({"count", "credentials"})
    public static class Credentials extends Structure {
        public int count;
        public Pointer credentials;
    }

    @Structure.FieldOrder({"count", "extensions"})
    public static class Extensions extends Structure {
        public int count;
        public Pointer extensions;
    }

    // Version 1 ends at flags. Passing this version lets older Windows releases use
    // the stable prefix without requiring newer SDK fields or OS support.
    @Structure.FieldOrder({"version", "timeout", "credentialList", "extensions",
            "attachment", "userVerification", "flags"})
    public static class AssertionOptions extends Structure {
        public int version, timeout;
        public Credentials credentialList = new Credentials();
        public Extensions extensions = new Extensions();
        public int attachment, userVerification, flags;
    }

    @Structure.FieldOrder({"version", "authenticatorLength", "authenticatorData",
            "signatureLength", "signature", "credential", "userLength", "userId"})
    public static class Assertion extends Structure {
        public int version, authenticatorLength;
        public Pointer authenticatorData;
        public int signatureLength;
        public Pointer signature;
        public Credential credential = new Credential();
        public int userLength;
        public Pointer userId;
        public Assertion(Pointer pointer) { super(pointer); read(); }
    }

    private WindowsWebAuthn() {}

    static int windowsApiVersion() {
        return Native.load("webauthn", Api.class).WebAuthNGetApiVersionNumber();
    }

    public static ObjectNode getAssertion(JsonNode options, String origin) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win"))
            throw new AuthService.AuthException("Security-key sign-in requires Windows on this client.");
        String rpId = options.path("rpId").asText("");
        String challenge = options.path("challenge").asText("");
        if (rpId.isBlank() || challenge.isBlank())
            throw new AuthService.AuthException("The server returned incomplete security-key options.");
        // Reject malformed challenges before invoking Windows Security.
        try { if (DECODER.decode(challenge).length < 16) throw new IllegalArgumentException(); }
        catch (IllegalArgumentException exception) {
            throw new AuthService.AuthException("The server returned an invalid security-key challenge.");
        }
        final Api api;
        try {
            api = Native.load("webauthn", Api.class);
            if (api.WebAuthNGetApiVersionNumber() < 1) throw new UnsatisfiedLinkError();
        } catch (UnsatisfiedLinkError error) {
            throw new AuthService.AuthException("Windows WebAuthn is unavailable on this computer.");
        }

        ObjectNode clientJson = JSON.createObjectNode();
        clientJson.put("type", "webauthn.get");
        clientJson.put("challenge", challenge);
        clientJson.put("origin", origin);
        clientJson.put("crossOrigin", false);
        byte[] clientBytes = clientJson.toString().getBytes(StandardCharsets.UTF_8);
        Memory clientMemory = new Memory(clientBytes.length);
        clientMemory.write(0, clientBytes, 0, clientBytes.length);
        ClientData client = new ClientData();
        client.version = 1;
        client.length = clientBytes.length;
        client.data = clientMemory;
        client.algorithm = new WString("SHA-256");
        client.write();

        AssertionOptions nativeOptions = new AssertionOptions();
        nativeOptions.version = 1;
        nativeOptions.timeout = Math.max(1000, Math.min(180000, options.path("timeout").asInt(180000)));
        nativeOptions.userVerification = switch (options.path("userVerification").asText("preferred")) {
            case "required" -> 1;
            case "discouraged" -> 3;
            default -> 2;
        };
        List<Memory> retained = new ArrayList<>();
        JsonNode allowed = options.path("allowCredentials");
        Credential[] entries = null;
        if (allowed.isArray() && !allowed.isEmpty()) {
            entries = (Credential[]) new Credential().toArray(allowed.size());
            for (int i = 0; i < entries.length; i++) {
                byte[] id;
                try { id = DECODER.decode(allowed.get(i).path("id").asText()); }
                catch (IllegalArgumentException error) {
                    throw new AuthService.AuthException("The server returned an invalid credential ID.");
                }
                if (id.length == 0) throw new AuthService.AuthException("The server returned an empty credential ID.");
                Memory memory = new Memory(id.length);
                memory.write(0, id, 0, id.length);
                retained.add(memory);
                entries[i].version = 1;
                entries[i].length = id.length;
                entries[i].id = memory;
                entries[i].type = new WString("public-key");
                entries[i].write();
            }
            nativeOptions.credentialList.count = entries.length;
            nativeOptions.credentialList.credentials = entries[0].getPointer();
        }
        nativeOptions.write();
        PointerByReference output = new PointerByReference();
        // Windows Security requires a real parent HWND for its modal authenticator UI.
        // This operation runs on a worker thread, so GetActiveWindow() cannot find
        // the JavaFX window. Use the foreground window as libfido2 does on Windows.
        Windows windows = Native.load("user32", Windows.class);
        Pointer parent = windows.GetForegroundWindow();
        if (parent == null) parent = windows.GetTopWindow(null);
        if (parent == null)
            throw new AuthService.AuthException("Cannot open Windows Security without a desktop window.");
        int hr = api.WebAuthNAuthenticatorGetAssertion(parent, new WString(rpId), client, nativeOptions, output);
        // Keep credential IDs and the client data alive through the synchronous call.
        java.lang.ref.Reference.reachabilityFence(entries);
        java.lang.ref.Reference.reachabilityFence(retained);
        java.lang.ref.Reference.reachabilityFence(clientMemory);
        if (hr != 0 || output.getValue() == null) {
            if (output.getValue() != null) api.WebAuthNFreeAssertion(output.getValue());
            Pointer errorName = api.WebAuthNGetErrorName(hr);
            String name = errorName == null ? "" : errorName.getWideString(0);
            throw new AuthService.AuthException(hr == 0x800704c7
                    ? "Security-key verification was cancelled."
                    : "Security-key verification failed (" + name + ", Windows 0x" + Integer.toHexString(hr) + ").");
        }
        try {
            Assertion assertion = new Assertion(output.getValue());
            if (assertion.credential.length <= 0 || assertion.credential.length > 65536
                    || assertion.authenticatorLength <= 0 || assertion.authenticatorLength > 65536
                    || assertion.signatureLength <= 0 || assertion.signatureLength > 65536)
                throw new AuthService.AuthException("Windows returned an invalid security-key assertion.");
            String id = encode(assertion.credential.id, assertion.credential.length);
            ObjectNode response = JSON.createObjectNode();
            response.put("clientDataJSON", ENCODER.encodeToString(clientBytes));
            response.put("authenticatorData", encode(assertion.authenticatorData, assertion.authenticatorLength));
            response.put("signature", encode(assertion.signature, assertion.signatureLength));
            if (assertion.userLength > 0 && assertion.userLength <= 65536)
                response.put("userHandle", encode(assertion.userId, assertion.userLength));
            else response.putNull("userHandle");
            ObjectNode credential = JSON.createObjectNode().put("id", id).put("rawId", id)
                    .put("type", "public-key");
            credential.set("response", response);
            // Required by the backend's WebAuthn credential parser even when
            // no client extensions were requested for this assertion.
            credential.set("clientExtensionResults", JSON.createObjectNode());
            return credential;
        } finally {
            api.WebAuthNFreeAssertion(output.getValue());
        }
    }

    private static String encode(Pointer source, int length) {
        if (source == null) throw new AuthService.AuthException("Windows returned incomplete security-key data.");
        return ENCODER.encodeToString(source.getByteArray(0, length));
    }
}
