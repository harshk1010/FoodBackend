package com.hk.service;

import com.hk.model.Address;
import com.hk.model.User;
import com.hk.repository.AddressRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AddressServiceImpl implements AddressService{

    @Autowired
    private AddressRepository addressRepository;

    @Override
    public List<Address> getUserAddresses(User user) {
        return addressRepository.findByUser(user);
    }

    @Override
    public void deleteAddress(Long addressId, User user) throws Exception {
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new Exception("Address not found with id: " + addressId));

        // Ensure the address belongs to the user
        if (!address.getUser().getId().equals(user.getId())) {
            throw new Exception("You are not authorized to delete this address.");
        }

        addressRepository.delete(address);
    }
}
