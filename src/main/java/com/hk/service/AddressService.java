package com.hk.service;

import com.hk.model.Address;
import com.hk.model.User;

import java.util.List;

public interface AddressService {

    List<Address> getUserAddresses(User user);
    void deleteAddress(Long addressId, User user) throws Exception;

}
