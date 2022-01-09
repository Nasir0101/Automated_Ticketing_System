package com.example.automatedticketingsystem.repository;


import com.example.automatedticketingsystem.entity.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<UserModel, String> {
    UserModel findByUserName(String userName);
}
