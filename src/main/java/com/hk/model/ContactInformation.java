package com.hk.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Entity;
import lombok.Data;

@Data
@Embeddable
public class ContactInformation {

    @Column(name = "email")
    private String email;

    private String mobile;

    private String twitter;

    private String instagram;
}
