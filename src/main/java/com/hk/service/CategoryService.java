package com.hk.service;

import com.hk.model.Category;

import java.util.List;

public interface CategoryService {

    public Category createCategory(String num, Long userId) throws Exception;

    public List<Category> findCategoryByRestaurant(Long id) throws Exception;

    public Category findCategoryById(Long id) throws Exception;
}
