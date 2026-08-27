package kakha.kudava.filedrivespring.services.lockbox;


import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public final class LockboxSignatureVerifier {

    private static final int ML_DSA_87_PUBLIC_KEY_LENGTH =
            2_592;

    private static final int ML_DSA_87_SIGNATURE_LENGTH =
            4_627;

    /**
     * Verifies pure ML-DSA-87 over the exact canonical message.
     *
     * The message is not pre-hashed before verification.
     */
    public void verify(
            byte[] publicKey,
            byte[] message,
            byte[] signature
    ) {
        requireExactLength(
                publicKey,
                ML_DSA_87_PUBLIC_KEY_LENGTH,
                "ML-DSA-87 public key"
        );

        if (message == null) {
            throw badRequest(
                    "Signature message is required."
            );
        }

        requireExactLength(
                signature,
                ML_DSA_87_SIGNATURE_LENGTH,
                "ML-DSA-87 signature"
        );

        final MLDSAPublicKeyParameters publicKeyParameters;

        try {
            publicKeyParameters =
                    new MLDSAPublicKeyParameters(
                            MLDSAParameters.ml_dsa_87,
                            publicKey
                    );
        } catch (RuntimeException exception) {
            throw badRequest(
                    "ML-DSA-87 public-key encoding is invalid."
            );
        }

        final boolean valid;

        try {
            MLDSASigner verifier = new MLDSASigner();

            verifier.init(
                    false,
                    publicKeyParameters
            );

            verifier.update(
                    message,
                    0,
                    message.length
            );

            valid = verifier.verifySignature(signature);
        } catch (RuntimeException exception) {
            throw badRequest(
                    "ML-DSA-87 signature verification failed."
            );
        }

        if (!valid) {
            throw badRequest(
                    "ML-DSA-87 signature is invalid."
            );
        }
    }

    private void requireExactLength(
            byte[] value,
            int expectedLength,
            String fieldName
    ) {
        if (value == null) {
            throw badRequest(
                    fieldName + " is required."
            );
        }

        if (value.length != expectedLength) {
            throw badRequest(
                    fieldName
                            + " must contain exactly "
                            + expectedLength
                            + " bytes."
            );
        }
    }

    private ResponseStatusException badRequest(
            String message
    ) {
        return new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                message
        );
    }
}
