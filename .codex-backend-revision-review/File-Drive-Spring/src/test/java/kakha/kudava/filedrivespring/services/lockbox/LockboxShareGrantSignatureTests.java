package kakha.kudava.filedrivespring.services.lockbox;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LockboxShareGrantSignatureTests {
    @Test
    void realMlDsa87SignatureBindsDomainAndExactEnvelopeBytes() throws Exception {
        MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
        generator.init(new MLDSAKeyGenerationParameters(
                new SecureRandom(),
                MLDSAParameters.ml_dsa_87
        ));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        MLDSAPrivateKeyParameters privateKey = (MLDSAPrivateKeyParameters) pair.getPrivate();
        MLDSAPublicKeyParameters publicKey = (MLDSAPublicKeyParameters) pair.getPublic();

        byte[] envelope = new byte[LockboxShareEnvelopeParser.PACKAGE_LENGTH];
        byte[] message = LockboxSharingService.signatureMessage(envelope);
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();

        LockboxSignatureVerifier verifier = new LockboxSignatureVerifier();
        assertDoesNotThrow(() -> verifier.verify(publicKey.getEncoded(), message, signature));

        byte[] changedEnvelope = envelope.clone();
        changedEnvelope[242] ^= 1;
        assertThrows(ResponseStatusException.class, () -> verifier.verify(
                publicKey.getEncoded(),
                LockboxSharingService.signatureMessage(changedEnvelope),
                signature
        ));

        byte[] changedDomain = message.clone();
        changedDomain[0] ^= 1;
        assertThrows(ResponseStatusException.class, () -> verifier.verify(
                publicKey.getEncoded(),
                changedDomain,
                signature
        ));

        byte[] changedSignature = signature.clone();
        changedSignature[0] ^= 1;
        assertThrows(ResponseStatusException.class, () -> verifier.verify(
                publicKey.getEncoded(),
                message,
                changedSignature
        ));
    }
}
