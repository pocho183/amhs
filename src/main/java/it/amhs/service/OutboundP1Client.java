package it.amhs.service;

import it.amhs.domain.AMHSMessage;

public interface OutboundP1Client {

    void relay(String endpoint, AMHSMessage message);
}
