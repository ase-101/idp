package io.mosip.idp.services;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.idp.core.dto.IdPTransaction;
import io.mosip.idp.core.dto.KycExchangeRequest;
import io.mosip.idp.core.dto.TokenRequest;
import io.mosip.idp.core.dto.TokenResponse;
import io.mosip.idp.core.exception.IdPException;
import io.mosip.idp.core.exception.InvalidClientException;
import io.mosip.idp.core.spi.AuthenticationWrapper;
import io.mosip.idp.core.spi.AuthorizationService;
import io.mosip.idp.core.spi.OAuthService;
import io.mosip.idp.core.spi.TokenService;
import io.mosip.idp.core.util.Constants;
import io.mosip.idp.core.util.ErrorConstants;
import io.mosip.idp.core.util.IdentityProviderUtil;
import io.mosip.idp.entity.ClientDetail;
import io.mosip.idp.repository.ClientDetailRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
public class OAuthServiceImpl implements OAuthService {


    @Autowired
    private ClientDetailRepository clientDetailRepository;

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    private AuthenticationWrapper authenticationWrapper;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private CacheUtilService cacheUtilService;

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private KeymanagerService keymanagerService;

    @Value("${mosip.idp.cache.key.hash.algorithm}")
    private String hashingAlgorithm;

    @Value("${mosip.idp.access-token.expire.seconds:60}")
    private int accessTokenExpireSeconds;


    @Override
    public TokenResponse getTokens(TokenRequest tokenRequest) throws IdPException {
        IdPTransaction transaction = cacheUtilService.getSetAuthenticatedTransaction(tokenRequest.getCode(), null, null);
        if (transaction == null)
            throw new IdPException(ErrorConstants.INVALID_CODE);

        if (!transaction.getClientId().equals(tokenRequest.getClient_id()))
            throw new IdPException(ErrorConstants.INVALID_CLIENT_ID);

        if (!transaction.getRedirectUri().equals(tokenRequest.getRedirect_uri()))
            throw new IdPException(ErrorConstants.INVALID_REDIRECT_URI);

        Optional<ClientDetail> result = clientDetailRepository.findByIdAndStatus(tokenRequest.getClient_id(),
                Constants.CLIENT_ACTIVE_STATUS);
        if (!result.isPresent())
            throw new InvalidClientException(ErrorConstants.INVALID_CLIENT_ID);

        authenticateClient(tokenRequest, result.get());

        IdentityProviderUtil.validateRedirectURI(result.get().getRedirectUris(), tokenRequest.getRedirect_uri());

        KycExchangeRequest kycExchangeRequest = new KycExchangeRequest();
        kycExchangeRequest.setClientId(tokenRequest.getClient_id());
        kycExchangeRequest.setKycToken(transaction.getKycToken());
        kycExchangeRequest.setAcceptedClaims(transaction.getAcceptedClaims());
        String encryptedKyc = authenticationWrapper.doKycExchange(kycExchangeRequest);

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccess_token(tokenService.getAccessToken(transaction));
        String accessTokenHash = IdentityProviderUtil.generateAccessTokenHash(tokenResponse.getAccess_token());
        transaction.setAHash(accessTokenHash);
        tokenResponse.setId_token(tokenService.getIDToken(transaction));
        tokenResponse.setExpires_in(accessTokenExpireSeconds);
        tokenResponse.setScope(transaction.getScopes());

        // cache kyc with access-token as key
        transaction.setIdHash(IdentityProviderUtil.generateAccessTokenHash(tokenResponse.getId_token()));
        transaction.setEncryptedKyc(encryptedKyc);
        cacheUtilService.getSetKycTransaction(accessTokenHash, transaction);

        return tokenResponse;
    }

    @Override
    public Map<String, Object> getJwks() throws Exception {
        var keyPairResponse = keymanagerService.getCertificate(Constants.IDP_SERVICE_APP_ID, Optional.empty());
        X509Certificate x509Cert = convertStringToX509Cert(keyPairResponse.getCertificate());

        var jwk = new RSAKey.Builder((RSAPublicKey)x509Cert.getPublicKey())
                .keyUse(KeyUse.ENCRYPTION)
                .keyID(UUID.randomUUID().toString())
                .algorithm(Algorithm.parse(x509Cert.getSigAlgName()))
                .build();

        return new JWKSet(jwk).toJSONObject();
    }

    private void authenticateClient(TokenRequest tokenRequest, ClientDetail clientDetail) throws IdPException {
        switch (tokenRequest.getClient_assertion_type()) {
            case JWT_BEARER_TYPE:
                validateJwtClientAssertion(clientDetail.getId(), clientDetail.getJwk(), tokenRequest.getClient_assertion());
                break;
            default:
                throw new IdPException(ErrorConstants.INVALID_ASSERTION_TYPE);
        }
    }


    private void validateJwtClientAssertion(String ClientId, String jwk, String clientAssertion) throws IdPException {
        if (clientAssertion == null || clientAssertion.isBlank())
            throw new IdPException(ErrorConstants.INVALID_ASSERTION);

        //verify signature
        //on valid signature, verify each claims on JWT payload
        tokenService.verifyClientAssertionToken(ClientId, jwk, clientAssertion);
    }

    private X509Certificate convertStringToX509Cert(String certificate) throws Exception {
        InputStream targetStream = new ByteArrayInputStream(certificate.getBytes());
        return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(targetStream);
    }
}
