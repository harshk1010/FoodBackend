package com.hk.service;

import com.hk.model.IngredientCategory;
import com.hk.model.IngredientsItem;

import java.util.List;

public interface IngredientService {

    public IngredientCategory createIngredientCategory(String name, Long restaurantId) throws Exception;

    public IngredientCategory findIngredientCategoryById(Long id) throws Exception;

    public List<IngredientCategory> findIngredientCategoryByRestaurantId(Long id) throws Exception;

    public IngredientsItem createIngredientItem(Long restaurantId,String ingredientName, Long categoryId) throws Exception;

    public List<IngredientsItem> findRestaurantsIngredient(Long restaurantId);

    public IngredientsItem updateStock(Long id) throws Exception;
}
