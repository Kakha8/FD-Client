package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TotpSerialServiceTest {
    private static final String SEED = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final String RESPONSE = "{\"type\":\"totp-enrollment\",\"secretBase32\":\"" + SEED
            + "\",\"algorithm\":\"SHA1\",\"digits\":6,\"period\":30}";

    @Test void acceptsSketchResponse() {
        assertEquals(SEED, TotpSerialService.parseSecret(RESPONSE));
    }

    @Test void ignoresBootMessagesAndMalformedResponses() {
        for (String input : new String[]{"Loaded TOTP secret from flash.", "READY: send ENROLL_EXPORT",
                "{bad json", "{\"error\":\"UNKNOWN_COMMAND\"}", RESPONSE + " garbage", "x".repeat(2048)}) {
            assertNull(TotpSerialService.parseSecret(input));
        }
    }

    @Test void rejectsWrongProfileAndInvalidSeed() {
        for (String input : new String[]{RESPONSE.replace("SHA1", "SHA256"), RESPONSE.replace(":6", ":8"),
                RESPONSE.replace(":30", ":60"), RESPONSE.replace(SEED, "012345"),
                RESPONSE.replace(SEED, SEED.toLowerCase()), RESPONSE.replace("totp-enrollment", "other")}) {
            assertNull(TotpSerialService.parseSecret(input));
        }
    }
}
