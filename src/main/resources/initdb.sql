CREATE TABLE amhs_messages (

    id SERIAL PRIMARY KEY,

    message_id VARCHAR(255) UNIQUE NOT NULL,

    sender VARCHAR(255) NOT NULL,

    recipient VARCHAR(255) NOT NULL,

    body TEXT NOT NULL,

    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);