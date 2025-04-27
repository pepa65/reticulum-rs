use std::collections::HashMap;

use crate::hash::AddressHash;




struct  DestinationRecord {

}


struct DestinationTable {
    map: HashMap<AddressHash, DestinationRecord>,
}
