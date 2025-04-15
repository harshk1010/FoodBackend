package com.hk.service;

import com.hk.model.Event;
import com.hk.model.Restaurant;
import com.hk.repository.EventRepository;
import com.hk.repository.RestaurantRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EventServiceImpl implements EventService{

    @Autowired
    private RestaurantRepository restaurantRepository;

    @Autowired
    private EventRepository eventRepository;

    @Override
    public Event createEvent(Event event, Long restaurantId) {

        Restaurant restaurant = restaurantRepository.findById(restaurantId)
                .orElseThrow(() -> new RuntimeException("Restaurant not found"));

        event.setRestaurant(restaurant);
        return eventRepository.save(event);

    }

    @Override
    public List<Event> getEventByRestaurant(Long restaurantId) {

        return eventRepository.findByRestaurantId(restaurantId);

    }

    @Override
    public void deleteEvent(Long eventId) {

        eventRepository.deleteById(eventId);

    }

    @Override
    public List<Event> getAllEvents() {
        return eventRepository.findAll();
    }
}
