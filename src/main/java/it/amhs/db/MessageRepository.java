package it.amhs.db;

import java.sql.*;

public class MessageRepository {

 private Connection conn;

 public MessageRepository(){

  try{

   conn =
    DriverManager.getConnection(
     "jdbc:postgresql://localhost/amhs",
     "amhs",
     "amhs"
    );

  }
  catch(Exception ex){

   ex.printStackTrace();

  }

 }

 public void save(byte[] msg){

  try{

   PreparedStatement ps =
    conn.prepareStatement(
     "insert into messages(content) values(?)"
    );

   ps.setBytes(1,msg);

   ps.execute();

  }
  catch(Exception ex){

   ex.printStackTrace();

  }

 }

 public byte[] load(String id){

  try{

   PreparedStatement ps =
    conn.prepareStatement(
     "select content from messages where message_id=?"
    );

   ps.setString(1,id);

   ResultSet rs=
    ps.executeQuery();

   rs.next();

   return rs.getBytes(1);

  }
  catch(Exception ex){

   ex.printStackTrace();

  }

  return null;

 }

}
