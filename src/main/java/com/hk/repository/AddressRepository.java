package com.hk.repository;

import com.hk.model.Address;
import com.hk.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AddressRepository extends JpaRepository<Address,Long> {

    List<Address> findByUser(User user);
}
