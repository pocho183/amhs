package it.amhs.dao;

import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AMHSDao {

    private final JdbcTemplate jdbc;
    
    public AMHSDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void saveMessage(String messageId, String sender, String recipient, String body) {
        String sql = "INSERT INTO amhs_messages(message_id, sender, recipient, body) VALUES (?, ?, ?, ?)";
        jdbc.update(sql, messageId, sender, recipient, body);
    }

    public String retrieveMessage(String messageId) {
        List<String> list = jdbc.query(
            "SELECT sender, recipient, body FROM amhs_messages WHERE message_id = ?",
            new Object[]{messageId},
            (rs, rowNum) -> "Message-ID: " + messageId + "\n" +
                             "From: " + rs.getString("sender") + "\n" +
                             "To: " + rs.getString("recipient") + "\n" +
                             "Body: " + rs.getString("body")
        );
        return list.isEmpty() ? null : list.get(0);
    }

    public List<String> retrieveAllMessages() {
        return jdbc.query(
            "SELECT message_id, sender, recipient, body FROM amhs_messages ORDER BY received_at ASC",
            (rs, rowNum) -> "Message-ID: " + rs.getString("message_id") + "\n" +
                            "From: " + rs.getString("sender") + "\n" +
                            "To: " + rs.getString("recipient") + "\n" +
                            "Body: " + rs.getString("body")
        );
    }
}
