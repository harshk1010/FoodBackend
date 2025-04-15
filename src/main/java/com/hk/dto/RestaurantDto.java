package com.hk.dto;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Data;

import java.util.List;

@Data
@Embeddable
public class RestaurantDto {

//    private String title;

    private String name;

    @Column(length = 1000)
    private List<String> images;

    private String description;
    private Long id;

//    public void getName() {
//    }
//
//    public void setName(String name) {
//    }
    // private Long resId;
}
