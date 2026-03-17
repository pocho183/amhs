package it.amhs.service.channel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import it.amhs.domain.AMHSChannel;
import it.amhs.repository.AMHSChannelRepository;

class AMHSChannelServiceTest {

    @Test
    void requireEnabledChannelCreatesDefaultChannelWhenDatabaseEnabledAndMissing() {
        AMHSChannelRepository repository = mock(AMHSChannelRepository.class);
        when(repository.findByNameIgnoreCase("ATFM")).thenReturn(Optional.empty());
        when(repository.save(any(AMHSChannel.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AMHSChannelService service = new AMHSChannelService(repository, true);

        AMHSChannel channel = service.requireEnabledChannel(null);

        assertEquals("ATFM", channel.getName());
        assertTrue(channel.isEnabled());
        verify(repository).save(any(AMHSChannel.class));
    }

    @Test
    void requireEnabledChannelReturnsEphemeralDefaultChannelWhenDatabaseDisabledAndMissing() {
        AMHSChannelRepository repository = mock(AMHSChannelRepository.class);
        when(repository.findByNameIgnoreCase("ATFM")).thenReturn(Optional.empty());

        AMHSChannelService service = new AMHSChannelService(repository, false);

        AMHSChannel channel = service.requireEnabledChannel("  ");

        assertEquals("ATFM", channel.getName());
        assertTrue(channel.isEnabled());
        verify(repository, never()).save(any(AMHSChannel.class));
    }

    @Test
    void requireEnabledChannelNormalizesNameToUppercase() {
        AMHSChannelRepository repository = mock(AMHSChannelRepository.class);
        AMHSChannel channel = new AMHSChannel();
        channel.setName("ATFM");
        channel.setEnabled(true);
        when(repository.findByNameIgnoreCase("ATFM")).thenReturn(Optional.of(channel));

        AMHSChannelService service = new AMHSChannelService(repository, true);

        AMHSChannel resolved = service.requireEnabledChannel("atfm");

        assertEquals("ATFM", resolved.getName());
        verify(repository).findByNameIgnoreCase("ATFM");
    }

    @Test
    void requireEnabledChannelRejectsUnknownNonDefaultChannel() {
        AMHSChannelRepository repository = mock(AMHSChannelRepository.class);
        when(repository.findByNameIgnoreCase(anyString())).thenReturn(Optional.empty());

        AMHSChannelService service = new AMHSChannelService(repository, true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> service.requireEnabledChannel("AFTN"));
        assertEquals("Unknown AMHS channel: AFTN", ex.getMessage());
    }
}
