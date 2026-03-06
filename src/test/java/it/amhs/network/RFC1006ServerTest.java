package it.amhs.network;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.rfc1006.RFC1006Service;

class RFC1006ServerTest {

    @Test
    void shouldRejectOutOfRangePort() throws Exception {
        RFC1006Service service = org.mockito.Mockito.mock(RFC1006Service.class);
        SSLContext sslContext = SSLContext.getDefault();

        assertThrows(IllegalArgumentException.class,
            () -> new RFC1006Server("0.0.0.0", 0, 8, false, false, sslContext, service));
        assertThrows(IllegalArgumentException.class,
            () -> new RFC1006Server("0.0.0.0", 70000, 8, false, false, sslContext, service));
    }

    @Test
    void shouldRejectNonPositiveMaxClientsAndAcceptValidConfiguration() throws Exception {
        RFC1006Service service = org.mockito.Mockito.mock(RFC1006Service.class);
        SSLContext sslContext = SSLContext.getDefault();

        assertThrows(IllegalArgumentException.class,
            () -> new RFC1006Server("0.0.0.0", 102, 0, false, false, sslContext, service));

        assertDoesNotThrow(() -> new RFC1006Server("0.0.0.0", 102, 16, false, false, sslContext, service));
    }
}
