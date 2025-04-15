package com.hk.controller;

import com.hk.dto.RestaurantDto;
import com.hk.model.Restaurant;
import com.hk.model.User;
import com.hk.request.CreateRestaurantRequest;
import com.hk.response.MessageResponse;
import com.hk.service.RestaurantService;
import com.hk.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/admin/restaurants")
public class AdminRestaurantController {

    @Autowired
    private RestaurantService restaurantService;

    @Autowired
    private UserService userService;

  //  @PreAuthorize("hasRole('RESTAURANT_OWNER')")
    @PostMapping()
    public ResponseEntity<Restaurant> createRestaurant (
        @RequestBody CreateRestaurantRequest req,
        @RequestHeader("Authorization") String jwt
        ) throws Exception {

        User user = userService.findUserByJwtToken(jwt);

        Restaurant restaurant = restaurantService.createRestaurant(req,user);

        return new ResponseEntity<>(restaurant, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Restaurant> updateRestaurant (
            @RequestBody CreateRestaurantRequest req,
            @RequestHeader("Authorization") String jwt,
            @PathVariable Long id
    ) throws Exception {

        User user = userService.findUserByJwtToken(jwt);

        Restaurant restaurant = restaurantService.updateRestaurant(id,req);

        return new ResponseEntity<>(restaurant, HttpStatus.CREATED);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<MessageResponse> deleteRestaurant (
            @RequestHeader("Authorization") String jwt,
            @PathVariable Long id
    ) throws Exception {

        User user = userService.findUserByJwtToken(jwt);

        restaurantService.deleteRestaurant(id);

        MessageResponse res = new MessageResponse();
        res.setMessage("restaurant deleted successfully");
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

//    @PutMapping("/{id}/status")
//    public ResponseEntity<Restaurant> updateRestaurantStatus (
//            @RequestHeader("Authorization") String jwt,
//            @PathVariable Long id
//    ) throws Exception {
//
//        User user = userService.findUserByJwtToken(jwt);
//
//        restaurantService.updateRestaurantStatus(id);
//
//        Restaurant restaurant = restaurantService.updateRestaurantStatus(id);
//        return new ResponseEntity<>(restaurant, HttpStatus.OK);
//    }

    @PutMapping("/{id}/status")
    public ResponseEntity<Restaurant> updateRestaurantStatus(
            @RequestHeader("Authorization") String jwt,
            @PathVariable Long id,
            @RequestBody Map<String, Object> updates // 👈 receive JSON body
    ) throws Exception {

        User user = userService.findUserByJwtToken(jwt);

        // Extract "open" from the body
        Boolean open = (Boolean) updates.get("open");

        Restaurant restaurant = restaurantService.updateRestaurantStatus(id, open);

        return new ResponseEntity<>(restaurant, HttpStatus.OK);
    }


    @GetMapping("/user")
    public ResponseEntity<Restaurant> findRestaurantByUserId (
            @RequestHeader("Authorization") String jwt
    ) throws Exception {

        User user = userService.findUserByJwtToken(jwt);


        Restaurant restaurant = restaurantService.getRestaurantByUserId(user.getId());
        return new ResponseEntity<>(restaurant, HttpStatus.OK);
    }
}

