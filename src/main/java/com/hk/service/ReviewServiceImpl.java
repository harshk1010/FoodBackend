package com.hk.service.impl;

import com.hk.model.Review;
import com.hk.model.User;
import com.hk.model.Restaurant;
import com.hk.repository.ReviewRepository;
import com.hk.repository.UserRepository;
import com.hk.repository.RestaurantRepository;
import com.hk.service.ReviewService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ReviewServiceImpl implements ReviewService {

    @Autowired
    private ReviewRepository reviewRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RestaurantRepository restaurantRepository;

    @Override
    public Review createReview(Long userId, Long restaurantId, Review review) throws Exception {
        // Corrected: use orElseThrow correctly
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new Exception("Address not found with id: " + userId));

        Restaurant restaurant = restaurantRepository.findById(restaurantId)
                .orElseThrow(() -> new Exception("Address not found with id: " + restaurantId));

        review.setUser(user);
        review.setRestaurant(restaurant);

        return reviewRepository.save(review);
    }

    @Override
    public List<Review> getAllReviewsForRestaurant(Long restaurantId) {
        return reviewRepository.findByRestaurantId(restaurantId); // Fix: lowercase "reviewRepository"
    }

    @Override
    public List<Review> getReviewsByUser(Long userId) {
        return reviewRepository.findByUserId(userId);
    }
}
