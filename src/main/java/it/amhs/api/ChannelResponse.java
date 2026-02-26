package it.amhs.api;

public record ChannelResponse(
	    Long id,
	    String name,
	    String expectedCn,
	    String expectedOu,
	    boolean enabled
	) { }