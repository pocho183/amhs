package it.amhs.domain;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class AMHSMessage {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	@Column(name = "message_id")
	String messageId;
	String sender;
	String recipient;
	String body;
	@Column(name = "received_at", updatable = false)
	@Temporal(TemporalType.TIMESTAMP)
	private Date receivedAt;
	
	@PrePersist
	protected void onCreate() {
		receivedAt = new Date();
	}
}
