package com.hk.service;

import com.hk.model.Event;

import java.util.List;

public interface EventService {

    Event createEvent(Event event, Long restaurantId);
    List<Event> getEventByRestaurant(Long restaurantId);
    void deleteEvent(Long eventId);
    List<Event> getAllEvents();
}
