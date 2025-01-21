import { Controller, Get } from '@nestjs/common';
import { UserService } from './user.service';
import { User } from './schemas/user.schema';

@Controller('user')
export class UserController {

    constructor(private readonly userService: UserService) {}

    @Get()
      async getusers(): Promise<User[]> {
        console.log('user ctrl');
        return this.userService.getsUsers();
      }
}
