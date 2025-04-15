package com.hk.service;

import com.hk.dto.RestaurantDto;
import com.hk.model.Address;
import com.hk.model.Restaurant;
import com.hk.model.User;
import com.hk.repository.AddressRepository;
import com.hk.repository.RestaurantRepository;
import com.hk.repository.UserRepository;
import com.hk.request.CreateRestaurantRequest;
import org.hibernate.id.factory.internal.AutoGenerationTypeStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class RestaurantServiceImp implements RestaurantService{

    @Autowired
    private RestaurantRepository restaurantRepository;

    @Autowired
    private AddressRepository addressRepository;

    @Autowired
    private UserRepository userRepository;


    @Override
    public Restaurant createRestaurant(CreateRestaurantRequest req, User user) {

        Address address = req.getAddress();
        address.setUser(user); // ✅ assign the user before saving
        Address savedAddress = addressRepository.save(address);
//        Address address = addressRepository.save(req.getAddress());
//
       Restaurant restaurant = new Restaurant();
      //  restaurant.setId(123L);
        restaurant.setAddress(savedAddress);
        restaurant.setContactInformation(req.getContactInformation());
        restaurant.setCuisineType(req.getCuisineType());
        restaurant.setDescription(req.getDescription());
        restaurant.setImages(req.getImages());
        restaurant.setName(req.getName());
        restaurant.setOpeningHours(req.getOpeningHours());
        restaurant.setRegistrationDate(LocalDateTime.now());
        restaurant.setOwner(user);
        restaurant.setOpen(true);

//        User savedUser = userRepository.save(user); // must be saved
//        restaurant.setOwner(savedUser);



        return restaurantRepository.save(restaurant);
    }

    @Override
    public Restaurant updateRestaurant(Long restaurantId, CreateRestaurantRequest updatedRestaurant) throws Exception {

        Restaurant restaurant = findRestaurantById(restaurantId);

        if(restaurant.getCuisineType()!=null) {
            restaurant.setCuisineType(updatedRestaurant.getCuisineType());
        }
        if(restaurant.getDescription()!=null) {
            restaurant.setDescription(updatedRestaurant.getDescription());
        }
        if(restaurant.getName()!=null) {
            restaurant.setName(updatedRestaurant.getName());
        }
        return restaurantRepository.save(restaurant);
    }


    @Override
    public void deleteRestaurant(Long restaurantId) throws Exception {

        Restaurant restaurant = findRestaurantById(restaurantId);

        restaurantRepository.delete(restaurant);
    }

    @Override
    public List<Restaurant> getAllRestaurant() {
        return restaurantRepository.findAll();
    }

    @Override
    public List<Restaurant> searchRestaurant(String keyword) {
        return restaurantRepository.findBySearchQuery(keyword);
    }

    @Override
    public Restaurant findRestaurantById(Long id) throws Exception {

        Optional<Restaurant> opt = restaurantRepository.findById(id);

        if(opt.isEmpty()) {
            throw new Exception("restaurant not found with id"+id);
        }
         return opt.get();
    }



    @Override
    public Restaurant getRestaurantByUserId(Long userId) throws Exception {

        Restaurant restaurant = restaurantRepository.findByOwnerId(userId);

        if(restaurant==null) {
            throw new Exception("Restaurant not found with owner id"+userId);
        }

        return restaurant;
    }

    @Override
    public RestaurantDto addToFavorites(Long restaurantId, User user) throws Exception {

        Restaurant restaurant = findRestaurantById(restaurantId);
        RestaurantDto dto = new RestaurantDto();
        dto.setName(restaurant.getName());
        dto.setDescription(restaurant.getDescription());
        dto.setImages(restaurant.getImages());
        dto.setId(restaurantId);

//        if(user.getFavorites().contains(dto)) {
//            user.getFavorites().remove(dto);
//        } else {
//            user.getFavorites().add(dto);
//        }

        boolean isFavorited = false;
        List<RestaurantDto> favorites = user.getFavorites();
        for(RestaurantDto favorite : favorites) {
            if(favorite.getId().equals(restaurantId)) {
                isFavorited = true;
                break;
            }
        }

        if(isFavorited) {
            favorites.removeIf(favorite -> favorite.getId().equals(restaurantId));
        } else {
            favorites.add(dto);
        }

        userRepository.save(user);
        return dto;
    }

    @Override
    public List<RestaurantDto> getAllFavorites(User user) {
        return user.getFavorites().stream()
                .map(fav -> {
                    RestaurantDto dto = new RestaurantDto();
                    dto.setId(fav.getId());
                    dto.setName(fav.getName());
                    dto.setDescription(fav.getDescription());
                    dto.setImages(fav.getImages());
          //          dto.setCuisineType(fav.getCuisineType());
            //        dto.setOpen(fav.isOpen());
             //       dto.setContactInformation(fav.getContactInformation());
              //      dto.setOpeningHours(fav.getOpeningHours());
                    return dto;
                })
                .collect(Collectors.toList());
    }


//    @Override
//    public Restaurant updateRestaurantStatus(Long id) throws Exception {
//
//        Restaurant restaurant = findRestaurantById(id);
//        restaurant.setOpen(!restaurant.isOpen());
//        return restaurantRepository.save(restaurant);
//    }

    @Override
    public Restaurant updateRestaurantStatus(Long id, Boolean open) throws Exception {
        Restaurant restaurant = restaurantRepository.findById(id)
                .orElseThrow(() -> new Exception("Restaurant not found"));

        restaurant.setOpen(open);
        return restaurantRepository.save(restaurant);
    }

}
