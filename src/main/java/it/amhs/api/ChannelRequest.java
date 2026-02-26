package it.amhs.api;

import jakarta.validation.constraints.NotBlank;

public record ChannelRequest(
	    @NotBlank String name,
	    String expectedCn,
	    String expectedOu,
	    Boolean enabled
	) {
	}
