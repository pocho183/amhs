package it.amhs.service.protocol.acse;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

@Component
public class AcseAssociationProtocol {

    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int AARQ_TAG = 0;
    private static final int AARE_TAG = 1;
    private static final int RLRQ_TAG = 2;
    private static final int RLRE_TAG = 3;
    private static final int ABRT_TAG = 4;

    private static final String DEFAULT_TRANSFER_SYNTAX_OID = "2.1.1";

    public byte[] encode(AcseModels.AcseApdu apdu) {
        if (apdu instanceof AcseModels.AARQApdu aarq) {
            return encodeAarq(aarq);
        }
        if (apdu instanceof AcseModels.AAREApdu aare) {
            return encodeAare(aare);
        }
        if (apdu instanceof AcseModels.RLRQApdu rlrq) {
            return encodeRlrq(rlrq);
        }
        if (apdu instanceof AcseModels.RLREApdu rlre) {
            return encodeRlre(rlre);
        }
        if (apdu instanceof AcseModels.ABRTApdu abrt) {
            return encodeAbrt(abrt);
        }
        throw new IllegalArgumentException("Unsupported ACSE APDU type: " + apdu.getClass().getSimpleName());
    }

    public AcseModels.AcseApdu decode(byte[] payload) {
        BerTlv apdu = BerCodec.decodeSingle(payload);
        if (apdu.tagClass() != TAG_CLASS_APPLICATION || !apdu.constructed()) {
            throw new IllegalArgumentException("ACSE APDU must use APPLICATION class constructed encoding");
        }
        return switch (apdu.tagNumber()) {
            case AARQ_TAG -> decodeAarq(apdu.value());
            case AARE_TAG -> decodeAare(apdu.value());
            case RLRQ_TAG -> decodeRlrq(apdu.value());
            case RLRE_TAG -> decodeRlre(apdu.value());
            case ABRT_TAG -> decodeAbrt(apdu.value());
            default -> throw new IllegalArgumentException("Unsupported ACSE APDU application tag [" + apdu.tagNumber() + "]");
        };
    }

    private byte[] encodeAarq(AcseModels.AARQApdu aarq) {
        byte[] payload = concat(
            encodeBitString(0, 0x80),
            encodeOid(1, aarq.applicationContextName()),
            aarq.calledApTitle().map(v -> encodeOid(2, v.objectIdentifier())).orElse(new byte[0]),
            aarq.calledAeQualifier().map(v -> encodeSmallInteger(3, v.value())).orElseGet(() -> aarq.calledAeTitle().map(v -> encodeGraphicString(3, v)).orElse(new byte[0])),
            aarq.callingApTitle().map(v -> encodeOid(6, v.objectIdentifier())).orElse(new byte[0]),
            aarq.callingAeQualifier().map(v -> encodeSmallInteger(7, v.value())).orElseGet(() -> aarq.callingAeTitle().map(v -> encodeGraphicString(7, v)).orElse(new byte[0])),
            aarq.authenticationValue().map(v -> encodeOctetString(12, v)).orElse(new byte[0]),
            aarq.presentationContexts().isEmpty() ? new byte[0] : encodePresentationContextDefinitionList(29, aarq.presentationContexts()),
            aarq.userInformation().map(v -> encodeUserInformation(30, v)).orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, AARQ_TAG, 0, payload.length, payload));
    }

    private AcseModels.AARQApdu decodeAarq(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        String appCtx = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
            .map(this::decodeOid)
            .orElseThrow(() -> new IllegalArgumentException("AARQ is missing application-context-name [1]"));

        Optional<String> calledAe = Optional.empty();
        Optional<AcseModels.AeQualifier> calledQualifier = Optional.empty();
        Optional<BerTlv> calledField = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 3);
        if (calledField.isPresent()) {
            if (isWrappedUniversalTag(calledField.get(), 25)) {
                calledAe = Optional.of(decodeGraphicString(calledField.get()));
            } else {
                calledQualifier = Optional.of(new AcseModels.AeQualifier(decodeSmallInteger(calledField.get())));
            }
        }

        Optional<String> callingAe = Optional.empty();
        Optional<AcseModels.AeQualifier> callingQualifier = Optional.empty();
        Optional<BerTlv> callingField = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 7);
        if (callingField.isPresent()) {
            if (isWrappedUniversalTag(callingField.get(), 25)) {
                callingAe = Optional.of(decodeGraphicString(callingField.get()));
            } else {
                callingQualifier = Optional.of(new AcseModels.AeQualifier(decodeSmallInteger(callingField.get())));
            }
        }

        Optional<AcseModels.ApTitle> calledApTitle = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 2)
            .map(v -> new AcseModels.ApTitle(decodeOid(v)));
        Optional<AcseModels.ApTitle> callingApTitle = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 6)
            .map(v -> new AcseModels.ApTitle(decodeOid(v)));
        Optional<byte[]> authValue = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 12)
            .map(this::decodeOctetString);
        Optional<byte[]> userInformation = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 30)
            .map(this::decodeUserInformation);
        PresentationContextParseResult presentationContexts = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 29)
            .map(this::decodePresentationContexts)
            .orElseGet(PresentationContextParseResult::empty);

        return new AcseModels.AARQApdu(
            appCtx,
            callingAe,
            calledAe,
            callingApTitle,
            callingQualifier,
            calledApTitle,
            calledQualifier,
            authValue,
            userInformation,
            presentationContexts.abstractSyntaxOids(),
            presentationContexts.proposedContexts()
        );
    }

    private byte[] encodeAare(AcseModels.AAREApdu aare) {
        int result = aare.accepted() ? 0 : 1;
        byte[] payload = concat(
            encodeResult(2, result),
            aare.resultSourceDiagnostic().map(this::encodeResultSourceDiagnostic).orElseGet(() -> aare.diagnostic().map(v -> encodeGraphicString(10, v)).orElse(new byte[0])),
            encodeAarePresentationNegotiation(aare),
            aare.userInformation().map(v -> encodeUserInformation(30, v)).orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, AARE_TAG, 0, payload.length, payload));
    }

    private AcseModels.AAREApdu decodeAare(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        int result = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 2)
            .map(this::decodeSmallInteger)
            .orElseThrow(() -> new IllegalArgumentException("AARE is missing result [2]"));

        Optional<AcseModels.ResultSourceDiagnostic> rsd = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 3)
            .map(this::decodeResultSourceDiagnostic);
        Optional<String> diagnostic = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 10)
            .map(this::decodeGraphicString);
        if (diagnostic.isEmpty() && rsd.isPresent()) {
            diagnostic = Optional.of("source=" + rsd.get().source() + ",diag=" + rsd.get().diagnostic());
        }

        Optional<byte[]> userInfo = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 30)
            .map(this::decodeUserInformation);
        PresentationContextParseResult presentationContexts = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 29)
            .map(this::decodePresentationContexts)
            .orElseGet(PresentationContextParseResult::empty);

        return new AcseModels.AAREApdu(result == 0, diagnostic, rsd, userInfo,
            presentationContexts.abstractSyntaxOids(), presentationContexts.acceptedContextIdentifiers());
    }

    private byte[] encodeRlrq(AcseModels.RLRQApdu rlrq) {
        byte[] payload = rlrq.reason().map(v -> encodeGraphicString(0, v)).orElse(new byte[0]);
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, RLRQ_TAG, 0, payload.length, payload));
    }

    private AcseModels.RLRQApdu decodeRlrq(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        Optional<String> reason = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeGraphicString);
        return new AcseModels.RLRQApdu(reason);
    }

    private byte[] encodeRlre(AcseModels.RLREApdu rlre) {
        byte[] payload = encodeResult(0, rlre.normal() ? 0 : 1);
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, RLRE_TAG, 0, payload.length, payload));
    }

    private AcseModels.RLREApdu decodeRlre(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        int result = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeSmallInteger)
            .orElse(0);
        return new AcseModels.RLREApdu(result == 0);
    }

    private byte[] encodeAbrt(AcseModels.ABRTApdu abrt) {
        byte[] payload = concat(
            encodeGraphicString(0, abrt.source()),
            abrt.diagnostic().map(v -> encodeGraphicString(1, v)).orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, ABRT_TAG, 0, payload.length, payload));
    }

    private AcseModels.ABRTApdu decodeAbrt(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        String source = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeGraphicString)
            .orElse("acse-service-user");
        Optional<String> diagnostic = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
            .map(this::decodeGraphicString);
        return new AcseModels.ABRTApdu(source, diagnostic);
    }

    private byte[] encodeGraphicString(int tagNumber, String text) {
        byte[] textBytes = text.trim().getBytes(StandardCharsets.US_ASCII);
        byte[] primitive = BerCodec.encode(new BerTlv(0, false, 25, 0, textBytes.length, textBytes));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, primitive.length, primitive));
    }

    private String decodeGraphicString(BerTlv wrapped) {
        BerTlv graphicString = BerCodec.decodeSingle(wrapped.value());
        if (!graphicString.isUniversal() || graphicString.tagNumber() != 25) {
            throw new IllegalArgumentException("ACSE expected GraphicString inside field [" + wrapped.tagNumber() + "]");
        }
        return new String(graphicString.value(), StandardCharsets.US_ASCII);
    }

    private byte[] encodeOid(int tagNumber, String dottedOid) {
        byte[] oidEncoded = encodeOidValue(dottedOid);
        byte[] oidTlv = BerCodec.encode(new BerTlv(0, false, 6, 0, oidEncoded.length, oidEncoded));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, oidTlv.length, oidTlv));
    }

    private String decodeOid(BerTlv wrappedOid) {
        BerTlv oidTlv = BerCodec.decodeSingle(wrappedOid.value());
        if (!oidTlv.isUniversal() || oidTlv.tagNumber() != 6) {
            throw new IllegalArgumentException("ACSE expected OBJECT IDENTIFIER inside field [" + wrappedOid.tagNumber() + "]");
        }
        return decodeOidValue(oidTlv.value());
    }

    private byte[] encodeBitString(int tagNumber, int bits) {
        byte[] bitString = BerCodec.encode(new BerTlv(0, false, 3, 0, 2, new byte[] {0x00, (byte) bits}));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, bitString.length, bitString));
    }

    private byte[] encodeResult(int tagNumber, int value) {
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, false, tagNumber, 0, 1, new byte[] {(byte) value}));
    }

    private byte[] encodeSmallInteger(int tagNumber, int value) {
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException("ACSE integer/ENUMERATED field must fit in one octet");
        }
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, false, tagNumber, 0, 1, new byte[] {(byte) value}));
    }

    private int decodeSmallInteger(BerTlv encoded) {
        if (encoded.value().length != 1) {
            throw new IllegalArgumentException("ACSE integer/ENUMERATED field must be one octet");
        }
        return encoded.value()[0] & 0xFF;
    }

    private byte[] encodeOctetString(int tagNumber, byte[] value) {
        byte[] octetString = BerCodec.encode(new BerTlv(0, false, 4, 0, value.length, value));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, octetString.length, octetString));
    }

    private byte[] decodeOctetString(BerTlv wrapped) {
        BerTlv octets = BerCodec.decodeSingle(wrapped.value());
        if (!octets.isUniversal() || octets.tagNumber() != 4) {
            throw new IllegalArgumentException("ACSE expected OCTET STRING inside field [" + wrapped.tagNumber() + "]");
        }
        return octets.value();
    }

    private byte[] encodeAarePresentationNegotiation(AcseModels.AAREApdu aare) {
        if (!aare.acceptedPresentationContextIds().isEmpty()) {
            return encodeAcceptedPresentationContextIds(29, aare.acceptedPresentationContextIds());
        }
        if (!aare.presentationContextOids().isEmpty()) {
            return encodePresentationContexts(29, aare.presentationContextOids());
        }
        return new byte[0];
    }

    private byte[] encodePresentationContexts(int tagNumber, List<String> contextOids) {
        List<PresentationContext> contexts = new ArrayList<>();
        int contextIdentifier = 1;
        for (String oid : contextOids) {
            contexts.add(new PresentationContext(contextIdentifier, oid, List.of(DEFAULT_TRANSFER_SYNTAX_OID)));
            contextIdentifier += 2;
        }
        return encodePresentationContextDefinitionList(tagNumber, contexts);
    }

    private byte[] encodePresentationContextDefinitionList(int tagNumber, List<PresentationContext> contexts) {
        List<byte[]> entries = new ArrayList<>();
        for (PresentationContext context : contexts) {
            context.validate();
            byte[] abstractSyntax = BerCodec.encode(new BerTlv(0, false, 6, 0,
                encodeOidValue(context.abstractSyntaxOid()).length, encodeOidValue(context.abstractSyntaxOid())));
            List<byte[]> transferSyntaxes = new ArrayList<>();
            for (String transferSyntaxOid : context.transferSyntaxOids()) {
                transferSyntaxes.add(BerCodec.encode(new BerTlv(0, false, 6, 0,
                    encodeOidValue(transferSyntaxOid).length, encodeOidValue(transferSyntaxOid))));
            }
            byte[] transferSyntaxListPayload = concat(transferSyntaxes.toArray(new byte[0][]));
            byte[] transferSyntaxList = BerCodec.encode(new BerTlv(0, true, 16, 0, transferSyntaxListPayload.length, transferSyntaxListPayload));
            byte[] contextIdentifierField = BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] {(byte) context.identifier()}));
            byte[] payload = concat(contextIdentifierField, abstractSyntax, transferSyntaxList);
            entries.add(BerCodec.encode(new BerTlv(0, true, 16, 0, payload.length, payload)));
        }
        byte[] sequence = concat(entries.toArray(new byte[0][]));
        byte[] wrappedSeq = BerCodec.encode(new BerTlv(0, true, 16, 0, sequence.length, sequence));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, wrappedSeq.length, wrappedSeq));
    }

    private byte[] encodeAcceptedPresentationContextIds(int tagNumber, Set<Integer> acceptedContextIds) {
        List<Integer> sortedIds = acceptedContextIds.stream().sorted().toList();
        List<byte[]> items = new ArrayList<>();
        for (Integer id : sortedIds) {
            if (id == null || id <= 0 || id % 2 == 0) {
                throw new IllegalArgumentException("Accepted presentation-context identifier must be an odd positive integer");
            }
            items.add(BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] {(byte) (id & 0xFF)})));
        }
        byte[] seqPayload = concat(items.toArray(new byte[0][]));
        byte[] wrappedSeq = BerCodec.encode(new BerTlv(0, true, 16, 0, seqPayload.length, seqPayload));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, wrappedSeq.length, wrappedSeq));
    }

    private PresentationContextParseResult decodePresentationContexts(BerTlv wrapped) {
        BerTlv seq = BerCodec.decodeSingle(wrapped.value());
        if (!seq.isUniversal() || seq.tagNumber() != 16) {
            throw new IllegalArgumentException("ACSE expected SEQUENCE for presentation contexts");
        }
        List<String> oids = new ArrayList<>();
        List<PresentationContext> proposed = new ArrayList<>();
        Set<Integer> accepted = new LinkedHashSet<>();
        Set<Integer> proposedIds = new LinkedHashSet<>();
        for (BerTlv item : BerCodec.decodeAll(seq.value())) {
            if (item.isUniversal() && !item.constructed() && item.tagNumber() == 2 && item.value().length == 1) {
                int id = item.value()[0] & 0xFF;
                if (id <= 0 || id % 2 == 0 || !accepted.add(id)) {
                    throw new IllegalArgumentException("ACSE presentation context identifier must be unique odd positive integer");
                }
                continue;
            }
            if (!item.isUniversal() || item.tagNumber() != 16) {
                throw new IllegalArgumentException("ACSE presentation context list item must be a SEQUENCE");
            }
            List<BerTlv> contextFields = BerCodec.decodeAll(item.value());
            if (contextFields.isEmpty()) {
                throw new IllegalArgumentException("ACSE presentation context item cannot be empty");
            }
            if (contextFields.size() == 1) {
                BerTlv oidTlv = contextFields.get(0);
                if (!oidTlv.isUniversal() || oidTlv.tagNumber() != 6) {
                    throw new IllegalArgumentException("ACSE presentation context item must contain OBJECT IDENTIFIER");
                }
                oids.add(decodeOidValue(oidTlv.value()));
                continue;
            }
            if (contextFields.size() != 3) {
                throw new IllegalArgumentException("ACSE presentation context item must contain identifier, abstract syntax and transfer syntax list");
            }

            BerTlv id = contextFields.get(0);
            if (!id.isUniversal() || id.tagNumber() != 2 || id.value().length != 1) {
                throw new IllegalArgumentException("ACSE presentation context item must start with INTEGER identifier");
            }
            int identifier = id.value()[0] & 0xFF;
            if (!proposedIds.add(identifier)) {
                throw new IllegalArgumentException("ACSE presentation context identifier must be unique odd positive integer");
            }

            BerTlv abstractSyntaxTlv = contextFields.get(1);
            if (!abstractSyntaxTlv.isUniversal() || abstractSyntaxTlv.tagNumber() != 6) {
                throw new IllegalArgumentException("ACSE presentation context abstract syntax must be OBJECT IDENTIFIER");
            }
            String abstractSyntaxOid = decodeOidValue(abstractSyntaxTlv.value());
            oids.add(abstractSyntaxOid);

            BerTlv transferSyntaxList = contextFields.get(2);
            if (!transferSyntaxList.isUniversal() || transferSyntaxList.tagNumber() != 16) {
                throw new IllegalArgumentException("ACSE presentation context transfer syntaxes must be a SEQUENCE");
            }
            List<BerTlv> transferSyntaxes = BerCodec.decodeAll(transferSyntaxList.value());
            if (transferSyntaxes.isEmpty()) {
                throw new IllegalArgumentException("ACSE presentation context transfer syntax list cannot be empty");
            }
            List<String> transferSyntaxOids = new ArrayList<>();
            for (BerTlv transferSyntax : transferSyntaxes) {
                if (!transferSyntax.isUniversal() || transferSyntax.tagNumber() != 6) {
                    throw new IllegalArgumentException("ACSE transfer syntax must be OBJECT IDENTIFIER");
                }
                transferSyntaxOids.add(decodeOidValue(transferSyntax.value()));
            }
            PresentationContext context = new PresentationContext(identifier, abstractSyntaxOid, transferSyntaxOids);
            context.validate();
            proposed.add(context);
        }
        if (oids.isEmpty() && proposed.isEmpty() && accepted.isEmpty()) {
            throw new IllegalArgumentException("ACSE presentation context list cannot be empty");
        }
        return new PresentationContextParseResult(List.copyOf(oids), List.copyOf(proposed), Set.copyOf(accepted));
    }

    private record PresentationContextParseResult(List<String> abstractSyntaxOids,
                                                  List<PresentationContext> proposedContexts,
                                                  Set<Integer> acceptedContextIdentifiers) {
        private static PresentationContextParseResult empty() {
            return new PresentationContextParseResult(List.of(), List.of(), Set.of());
        }
    }

    private byte[] encodeUserInformation(int tagNumber, byte[] associationInformation) {
        byte[] encodedAssociation = BerCodec.encode(new BerTlv(0, false, 4, 0, associationInformation.length, associationInformation));
        byte[] external = BerCodec.encode(new BerTlv(0, true, 8, 0, encodedAssociation.length, encodedAssociation));
        byte[] sequence = BerCodec.encode(new BerTlv(0, true, 16, 0, external.length, external));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, sequence.length, sequence));
    }

    private byte[] decodeUserInformation(BerTlv wrapped) {
        BerTlv sequence = BerCodec.decodeSingle(wrapped.value());
        if (!sequence.isUniversal() || sequence.tagNumber() != 16) {
            throw new IllegalArgumentException("ACSE expected SEQUENCE in user-information");
        }
        List<BerTlv> elements = BerCodec.decodeAll(sequence.value());
        if (elements.isEmpty()) {
            return new byte[0];
        }
        for (BerTlv element : elements) {
            Optional<byte[]> associationInfo = decodeUserInformationElement(element);
            if (associationInfo.isPresent()) {
                return associationInfo.get();
            }
        }
        throw new IllegalArgumentException("ACSE user-information does not contain a decodable association-information payload");
    }

    private Optional<byte[]> decodeUserInformationElement(BerTlv element) {
        if (element.isUniversal() && element.tagNumber() == 4) {
            return Optional.of(element.value());
        }
        if (element.isUniversal() && element.tagNumber() == 8) {
            return decodeExternalAssociationInformation(element);
        }
        return Optional.empty();
    }

    private Optional<byte[]> decodeExternalAssociationInformation(BerTlv external) {
        List<BerTlv> externalElements = BerCodec.decodeAll(external.value());
        for (BerTlv component : externalElements) {
            if (component.isUniversal() && component.tagNumber() == 4) {
                return Optional.of(component.value());
            }
            if (component.tagClass() == TAG_CLASS_CONTEXT && component.tagNumber() == 1) {
                return Optional.of(component.value());
            }
            if (component.tagClass() == TAG_CLASS_CONTEXT && component.tagNumber() == 2 && component.value().length > 0) {
                return Optional.of(java.util.Arrays.copyOfRange(component.value(), 1, component.value().length));
            }
            if (component.tagClass() == TAG_CLASS_CONTEXT && component.tagNumber() == 0 && component.constructed()) {
                BerTlv inner = BerCodec.decodeSingle(component.value());
                if (inner.isUniversal() && inner.tagNumber() == 4) {
                    return Optional.of(inner.value());
                }
                return Optional.of(BerCodec.encode(inner));
            }
        }
        return Optional.empty();
    }

    private byte[] encodeResultSourceDiagnostic(AcseModels.ResultSourceDiagnostic rsd) {
        byte[] source = encodeSmallInteger(0, rsd.source());
        byte[] diagnostic = encodeSmallInteger(1, rsd.diagnostic());
        byte[] payload = concat(source, diagnostic);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, 3, 0, payload.length, payload));
    }

    private AcseModels.ResultSourceDiagnostic decodeResultSourceDiagnostic(BerTlv wrapped) {
        List<BerTlv> fields = BerCodec.decodeAll(wrapped.value());
        int source = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0).map(this::decodeSmallInteger).orElse(0);
        int diagnostic = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1).map(this::decodeSmallInteger).orElse(0);
        return new AcseModels.ResultSourceDiagnostic(source, diagnostic);
    }

    private boolean isWrappedUniversalTag(BerTlv wrapped, int universalTag) {
        BerTlv inner = BerCodec.decodeSingle(wrapped.value());
        return inner.isUniversal() && inner.tagNumber() == universalTag;
    }

    private byte[] encodeOidValue(String oid) {
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID must contain at least two arcs");
        }
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);
        if (first < 0 || first > 2 || second < 0 || (first < 2 && second > 39)) {
            throw new IllegalArgumentException("Invalid first OID arcs");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((first * 40) + second);
        for (int i = 2; i < parts.length; i++) {
            long arc = Long.parseLong(parts[i]);
            if (arc < 0) {
                throw new IllegalArgumentException("OID arcs must be >= 0");
            }
            writeBase128(out, arc);
        }
        return out.toByteArray();
    }

    private String decodeOidValue(byte[] oidBytes) {
        if (oidBytes.length == 0) {
            throw new IllegalArgumentException("BER OBJECT IDENTIFIER is empty");
        }
        int first = oidBytes[0] & 0xFF;
        StringBuilder oid = new StringBuilder();
        oid.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = 1; i < oidBytes.length; i++) {
            int octet = oidBytes[i] & 0xFF;
            value = (value << 7) | (octet & 0x7F);
            if ((octet & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }
        if (value != 0) {
            throw new IllegalArgumentException("Invalid BER OBJECT IDENTIFIER encoding");
        }
        return oid.toString();
    }

    private void writeBase128(ByteArrayOutputStream out, long arc) {
        int count = 0;
        int[] tmp = new int[10];
        tmp[count++] = (int) (arc & 0x7F);
        arc >>= 7;
        while (arc > 0) {
            tmp[count++] = (int) (arc & 0x7F);
            arc >>= 7;
        }
        for (int i = count - 1; i >= 0; i--) {
            int value = tmp[i];
            if (i != 0) {
                value |= 0x80;
            }
            out.write(value);
        }
    }

    private byte[] concat(byte[]... chunks) {
        int total = 0;
        for (byte[] chunk : chunks) {
            total += chunk.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }
}
