package com.hk.service;

import com.hk.model.Review;
import com.hk.model.User;
import com.hk.model.Restaurant;

import java.util.List;

public interface ReviewService {

    Review createReview(Long userId, Long restaurantId, Review review) throws Exception;

    List<Review> getAllReviewsForRestaurant(Long restaurantId);

    List<Review> getReviewsByUser(Long userId);
}
