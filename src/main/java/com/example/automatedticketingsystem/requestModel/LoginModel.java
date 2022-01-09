package com.example.automatedticketingsystem.requestModel;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginModel {
    private String userName;
    private String password;
}
