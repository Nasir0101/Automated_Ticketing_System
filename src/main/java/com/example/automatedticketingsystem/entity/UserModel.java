package com.example.automatedticketingsystem.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "USER_TBL")
public class UserModel {
    @Id
    @GeneratedValue(generator = "system-uuid")
    @GenericGenerator(name = "system-uuid", strategy = "uuid")
    private String id;
    @Column(name = "userName")
    private String userName;
    @Column(name = "password")
    private String password;
    @Column(name = "role")
    private String role;
}
