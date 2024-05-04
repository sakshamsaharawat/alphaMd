import { User } from "../entities/user.entity";
import { BooleanMessage } from "./boolean-message.interface";

export interface CreateUser extends BooleanMessage{
    newUser: User
}