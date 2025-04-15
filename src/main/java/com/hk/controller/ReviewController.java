package com.hk.controller;

import com.hk.model.Review;
import com.hk.service.ReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reviews")
public class ReviewController {

    @Autowired
    private ReviewService reviewService;

    // Create a review for a restaurant
    @PostMapping("/create/{userId}/{restaurantId}")
    public ResponseEntity<Review> createReview(@PathVariable Long userId,
                                               @PathVariable Long restaurantId,
                                               @RequestBody Review review) {
        try {
            Review savedReview = reviewService.createReview(userId, restaurantId, review);
            return new ResponseEntity<>(savedReview, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    // Get all reviews for a specific restaurant
    @GetMapping("/restaurant/{restaurantId}")
    public ResponseEntity<List<Review>> getAllReviewsForRestaurant(@PathVariable Long restaurantId) {
        List<Review> reviews = reviewService.getAllReviewsForRestaurant(restaurantId);
        if (reviews.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(reviews, HttpStatus.OK);
    }

    // Get all reviews by a specific user
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Review>> getReviewsByUser(@PathVariable Long userId) {
        List<Review> reviews = reviewService.getReviewsByUser(userId);
        if (reviews.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(reviews, HttpStatus.OK);
    }
}
