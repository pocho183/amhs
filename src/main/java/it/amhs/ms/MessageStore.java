package it.amhs.ms;

import it.amhs.db.MessageRepository;

public class MessageStore {

 public byte[] fetch(String id){

  return new MessageRepository()
   .load(id);

 }

}