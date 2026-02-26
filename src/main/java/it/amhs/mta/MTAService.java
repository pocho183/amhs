package it.amhs.mta;

import it.amhs.db.MessageRepository;

public class MTAService {

 public void transfer(byte[] content){

  MessageRepository repo =
   new MessageRepository();

  repo.save(content);

 }

}
