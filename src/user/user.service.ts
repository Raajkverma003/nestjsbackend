import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/user/schemas/user.schema';
@Injectable()
export class UserService {

    constructor(
        @InjectModel(User.name) private userModel: Model<User>
      ) {}

      async getsUsers(): Promise<User[]> {
        const usrsobj = await  this.userModel.find();
        console.log('user service');
        console.log(usrsobj);
        return usrsobj;
      }
    
        async getUserById(id: string) {
        return this.userModel.findById(id).populate(['settings', 'posts']);
      }
    
}
