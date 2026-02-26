package it.amhs.protocol;

public class ACSEService {

 public void handle(byte[] data){

  // decode A-ASSOCIATE

  ROSEService rose =
   new ROSEService();

  rose.process(data);

 }

}